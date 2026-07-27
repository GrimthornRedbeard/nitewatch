// Package rdap looks up who registered an address or a domain.
//
// PRIVACY: this is the ONE place in NiteWatch that queries a third party about
// something specific to the user's machine. An RDAP request tells the registry
// which address you are asking about, which is exactly the leak the offline
// ownership dataset exists to avoid.
//
// It is therefore never automatic. Nothing here runs on ingest, on a schedule,
// or in the background. It runs only when a person clicks "look up
// registration" about one destination they are already investigating — at which
// point they have made an informed choice, and a single query is a reasonable
// price for the answer. The UI says plainly that it contacts an external
// service before it does so.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Registration is what a lookup tells us, flattened into what a person cares
// about. RDAP responses are deeply nested and inconsistent between registries;
// this is the useful subset, normalised.
type Registration struct {
	Query string `json:"query"`
	Kind  string `json:"kind"` // "ip" or "domain"

	// Network/registry facts.
	Name    string `json:"name,omitempty"`    // network or domain name
	Range   string `json:"range,omitempty"`   // allocated address range
	Handle  string `json:"handle,omitempty"`  // registry handle
	Country string `json:"country,omitempty"` // registered country
	Source  string `json:"source,omitempty"`  // which registry answered

	// Who is responsible.
	Registrant string `json:"registrant,omitempty"`
	// Contact is the administrative or technical point of contact, kept apart
	// from Registrant because it is often a named individual rather than the
	// organisation that holds the address.
	Contact   string `json:"contact,omitempty"`
	Registrar string `json:"registrar,omitempty"`
	Abuse     string `json:"abuse,omitempty"`

	// Dates. Age is the single most useful fact here: a domain registered days
	// ago behaves very differently from one registered a decade ago.
	Registered string `json:"registered,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Changed    string `json:"changed,omitempty"`
	// AgeDays is -1 when unknown.
	AgeDays int `json:"ageDays"`

	Nameservers []string `json:"nameservers,omitempty"`
	Status      []string `json:"status,omitempty"`
	// Note carries a plain-English observation worth surfacing, e.g. that the
	// domain was registered very recently.
	Note string `json:"note,omitempty"`
}

// Client performs lookups, caching results so repeated clicks on the same
// destination do not repeatedly announce the user's interest to a registry.
type Client struct {
	mu    sync.Mutex
	cache map[string]cached
	http  *http.Client
	// BaseURL is the RDAP bootstrap service. rdap.org redirects to whichever
	// registry is authoritative, which avoids shipping the RIR mapping.
	BaseURL string
}

type cached struct {
	reg Registration
	at  time.Time
}

// CacheTTL: registration data changes on the order of months. An hour is
// generous for a session and keeps repeat clicks off the network entirely.
const CacheTTL = time.Hour

func New() *Client {
	return &Client{
		cache:   map[string]cached{},
		http:    &http.Client{Timeout: 12 * time.Second},
		BaseURL: "https://rdap.org",
	}
}

// Lookup resolves an address or domain. The caller is responsible for ensuring
// a person asked for it.
func (c *Client) Lookup(ctx context.Context, query string) (Registration, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return Registration{}, fmt.Errorf("nothing to look up")
	}

	kind, err := classify(query)
	if err != nil {
		return Registration{}, err
	}

	c.mu.Lock()
	if hit, ok := c.cache[query]; ok && time.Since(hit.at) < CacheTTL {
		c.mu.Unlock()
		return hit.reg, nil
	}
	c.mu.Unlock()

	url := c.BaseURL + "/" + kind + "/" + query
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Registration{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Registration{}, fmt.Errorf("could not reach the registry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Registration{}, fmt.Errorf("no registration record found for %s", query)
	}
	if resp.StatusCode != http.StatusOK {
		return Registration{}, fmt.Errorf("registry returned %s", resp.Status)
	}

	// Cap the body: we are parsing a response from a server we do not control,
	// and registry records are kilobytes, not megabytes.
	var raw rdapResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return Registration{}, fmt.Errorf("could not read the registry's answer: %w", err)
	}

	reg := raw.normalise(query, kind)
	c.mu.Lock()
	c.cache[query] = cached{reg: reg, at: time.Now()}
	c.mu.Unlock()
	return reg, nil
}

// classify decides whether the query is an address or a domain, and refuses
// anything that is neither.
//
// The query string ends up in an outbound URL path, so it cannot be trusted
// merely because it arrived from our own dashboard: a rebound page or a script
// that got the token could otherwise use this endpoint to make the agent issue
// arbitrary requests. Only a literal IP or a syntactically valid hostname is
// allowed through.
func classify(query string) (string, error) {
	if ip := net.ParseIP(query); ip != nil {
		// Private, loopback and link-local addresses have no registry record —
		// they are the user's own network. Asking about them tells a stranger
		// about the user's LAN for no possible answer.
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || isSharedCGNAT(ip) {
			return "", fmt.Errorf("%s is on a private or local network, so there is no public registration to look up", query)
		}
		return "ip", nil
	}
	if !validHostname(query) {
		return "", fmt.Errorf("%q is not an address or a domain name", query)
	}
	return "domain", nil
}

// isSharedCGNAT covers 100.64.0.0/10, used by carrier NAT and by VPN meshes
// like Tailscale. Global-unicast by type, not publicly registered in practice.
func isSharedCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// validHostname accepts only what a DNS name may contain, which excludes every
// character that could change the meaning of the outbound URL.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// rdapResponse is the subset of the RDAP schema worth decoding.
type rdapResponse struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	Name            string       `json:"name"`
	LDHName         string       `json:"ldhName"`
	Country         string       `json:"country"`
	StartAddress    string       `json:"startAddress"`
	EndAddress      string       `json:"endAddress"`
	Port43          string       `json:"port43"`
	Status          []string     `json:"status"`
	Events          []rdapEvent  `json:"events"`
	Entities        []rdapEntity `json:"entities"`
	Nameservers     []rdapNS     `json:"nameservers"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Handle     string       `json:"handle"`
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

func (r rdapResponse) normalise(query, kind string) Registration {
	reg := Registration{Query: query, Kind: kind, AgeDays: -1,
		Handle: r.Handle, Country: r.Country, Status: r.Status}

	reg.Name = r.Name
	if reg.Name == "" {
		reg.Name = r.LDHName
	}
	if r.StartAddress != "" && r.EndAddress != "" {
		reg.Range = r.StartAddress + " – " + r.EndAddress
	}
	if r.Port43 != "" {
		reg.Source = r.Port43
	}

	for _, e := range r.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			reg.Registered = e.Date
		case "expiration":
			reg.Expires = e.Date
		case "last changed", "last update of rdap database":
			if reg.Changed == "" {
				reg.Changed = e.Date
			}
		}
	}
	if reg.Registered != "" {
		if t, err := time.Parse(time.RFC3339, reg.Registered); err == nil {
			reg.AgeDays = int(time.Since(t).Hours() / 24)
		}
	}

	// Entities carry the humans and organisations, nested and role-tagged.
	var walk func(ents []rdapEntity)
	walk = func(ents []rdapEntity) {
		for _, e := range ents {
			name := vcardName(e.VCardArray)
			for _, role := range e.Roles {
				switch strings.ToLower(role) {
				// Only the registrant is the holder. Registries commonly list an
				// administrative or technical contact first, and against real
				// ARIN data that meant a duty engineer's personal name was shown
				// as the owner of a CDN's address block — wrong, and needlessly
				// exposing of an individual.
				case "registrant":
					if reg.Registrant == "" && name != "" {
						reg.Registrant = name
					}
				case "administrative", "technical":
					if reg.Contact == "" && name != "" {
						reg.Contact = name
					}
				case "registrar":
					if reg.Registrar == "" && name != "" {
						reg.Registrar = name
					}
				case "abuse":
					if reg.Abuse == "" {
						if em := vcardEmail(e.VCardArray); em != "" {
							reg.Abuse = em
						} else if name != "" {
							reg.Abuse = name
						}
					}
				}
			}
			walk(e.Entities)
		}
	}
	walk(r.Entities)

	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			reg.Nameservers = append(reg.Nameservers, ns.LDHName)
		}
	}

	reg.Note = observation(reg)
	return reg
}

// observation surfaces the one fact most worth a person's attention. Domain age
// is the strongest signal RDAP offers: infrastructure registered days ago and
// already receiving traffic is a well-known pattern, while a decade-old domain
// is evidence of nothing in particular.
func observation(reg Registration) string {
	if reg.Kind != "domain" || reg.AgeDays < 0 {
		return ""
	}
	switch {
	case reg.AgeDays <= 30:
		return fmt.Sprintf("This domain was registered only %d days ago. Brand-new domains "+
			"are common in scams and malware, because the old ones get blocked.", reg.AgeDays)
	case reg.AgeDays <= 180:
		return fmt.Sprintf("This domain is about %d months old — recent, though not brand new.",
			reg.AgeDays/30)
	case reg.AgeDays >= 3650:
		return "This domain has been registered for over ten years, which is typical of an established service."
	}
	return ""
}

// vcardName pulls the formatted name from a jCard, whose shape is
// ["vcard", [["fn", {}, "text", "Example Inc"], ...]].
func vcardName(v []any) string { return vcardField(v, "fn", "org") }

func vcardEmail(v []any) string { return vcardField(v, "email") }

func vcardField(v []any, keys ...string) string {
	if len(v) < 2 {
		return ""
	}
	entries, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, want := range keys {
		for _, e := range entries {
			row, ok := e.([]any)
			if !ok || len(row) < 4 {
				continue
			}
			name, _ := row[0].(string)
			if !strings.EqualFold(name, want) {
				continue
			}
			switch val := row[3].(type) {
			case string:
				if val != "" {
					return val
				}
			case []any:
				// Structured values (an "org" can be a list); take the first.
				for _, p := range val {
					if s, ok := p.(string); ok && s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}
