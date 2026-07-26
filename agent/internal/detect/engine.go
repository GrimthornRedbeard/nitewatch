// Package detect evaluates rules against connections as they are recorded.
//
// Detectors are Go functions (matching needs ledger history, intel lookups, and
// causal-graph state that YAML cannot express); rules are data that bind a
// detector to a severity and the words shown to the user. A rule fires only if
// its detector matches AND the suppression gates pass.
package detect

import (
	"strings"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

// Subject is everything known about one connection at detection time.
type Subject struct {
	Event  event.NormalizedEvent
	Conn   ledger.Connection
	Recon  recon.Info
	Domain string // the observed or resolved name, "" if none

	// HadDNS reports whether a DNS lookup by this process produced this
	// address. Distinct from Domain != "": a reverse-DNS name proves nothing
	// about whether the program looked the address up.
	HadDNS bool
	// FirstContact is true when this process has never reached this
	// destination before.
	FirstContact bool
}

// Detection is a rule that matched, with the data its templates need.
type Detection struct {
	Rule   *rules.Rule
	Fields map[string]any
}

// Detector decides whether a subject matches. It returns the template fields to
// merge on a match, or nil for no match.
type Detector func(s Subject, e *Engine) map[string]any

// Engine evaluates the loaded rule set against subjects.
type Engine struct {
	set   *rules.Set
	intel *intel.Store
	dets  map[string]Detector
}

// New builds an engine. A nil intel store simply disables feed-based detectors.
func New(set *rules.Set, feeds *intel.Store) *Engine {
	e := &Engine{set: set, intel: feeds}
	e.dets = map[string]Detector{
		"connection-intel-hit":  detectIntelHit,
		"raw-ip-no-dns":         detectRawIPNoDNS,
		"unsigned-outbound":     detectUnsignedOutbound,
		"foreign-first-contact": detectForeignFirstContact,
	}
	return e
}

// Evaluate runs every detector that has rules bound to it and returns the
// detections that matched.
func (e *Engine) Evaluate(s Subject) []Detection {
	var out []Detection
	for name, det := range e.dets {
		bound := e.set.For(name)
		if len(bound) == 0 {
			continue // no rule cares about this detector; skip the work
		}
		fields := det(s, e)
		if fields == nil {
			continue
		}
		base := baseFields(s)
		for k, v := range fields {
			base[k] = v
		}
		// Rules are severity-sorted; the most serious one for a detector wins,
		// so one condition cannot produce a pile of duplicate alerts.
		out = append(out, Detection{Rule: bound[0], Fields: base})
	}
	return out
}

// baseFields are available to every rule template.
func baseFields(s Subject) map[string]any {
	dest := s.Domain
	if dest == "" {
		dest = s.Conn.RemoteIP
	}
	return map[string]any{
		"ProcessName": shortName(s.Conn.Image),
		"ImagePath":   s.Conn.Image,
		"PID":         s.Conn.PID,
		"Destination": dest,
		"RemoteIP":    s.Conn.RemoteIP,
		"RemotePort":  s.Conn.RemotePort,
		"Domain":      s.Domain,
		"Owner":       s.Recon.Org,
		"Country":     s.Recon.Country,
		"ASN":         s.Recon.ASN,
	}
}

func shortName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	if p == "" {
		return "An unknown program"
	}
	return p
}

// --- detectors ---

// detectIntelHit fires when the destination is on a malicious feed. Context
// feeds (Tor) never fire alone — see the package docs in internal/intel.
func detectIntelHit(s Subject, e *Engine) map[string]any {
	if e.intel == nil {
		return nil
	}
	if m, ok := e.intel.FlagIP(s.Conn.RemoteIP); ok && m.Confidence == intel.Malicious {
		return map[string]any{"FeedName": m.Feed, "FeedReason": m.Reason}
	}
	if s.Domain != "" {
		if m, ok := e.intel.FlagDomain(s.Domain); ok && m.Confidence == intel.Malicious {
			return map[string]any{"FeedName": m.Feed, "FeedReason": m.Reason}
		}
	}
	return nil
}

// detectRawIPNoDNS fires when a program dials a bare address it never looked up.
// Malware often carries hardcoded addresses precisely to avoid leaving DNS
// evidence.
//
// The hard part is that "no lookup was observed" is NOT the same as "no lookup
// happened", and the gap is large enough to sink the rule if ignored:
//
//   - DNS-over-HTTPS. Firefox, Chrome, Edge and Windows itself increasingly
//     resolve over HTTPS, which produces no DNS-Client telemetry at all. Every
//     connection a DoH browser makes looks like a bare-address contact.
//   - Cached and configured addresses. A program that resolved a name an hour
//     ago, or reads an address from config, legitimately connects with no
//     lookup nearby.
//   - CDN and cloud infrastructure. Content is served from pools of addresses
//     that clients reach directly and constantly.
//
// So a bare-address contact to SHARED INFRASTRUCTURE is not evidence of
// anything — it is the normal shape of the modern web. The rule therefore fires
// only for destinations on networks that are not shared hosting. Traffic to
// genuinely malicious infrastructure is caught by the feed rule regardless of
// how the address was obtained.
func detectRawIPNoDNS(s Subject, _ *Engine) map[string]any {
	if s.HadDNS || s.Conn.Inbound || !s.FirstContact {
		return nil
	}
	// A name from any source (including reverse DNS) means the destination is
	// identifiable, which is the opposite of hiding.
	if s.Domain != "" {
		return nil
	}
	// Ownership data is what makes this signal judgeable, and it loads in the
	// background over a 45MB download. Firing while it is unavailable would
	// mean every restart produces the CDN false positives this rule is
	// explicitly meant to avoid. A weak signal we cannot contextualise is not
	// worth interrupting someone over — better to miss it than to cry wolf on
	// every boot.
	if s.Recon.Org == "" {
		return nil
	}
	if SharedInfrastructure(s.Recon.Org) {
		return nil
	}
	return map[string]any{}
}

// sharedInfraTokens identify networks that host everyone's traffic. Substring
// matching is correct here, unlike for publisher trust: this list only
// SUPPRESSES a weak signal, so a false match costs sensitivity rather than
// granting trust, and AS names carry inconsistent suffixes
// ("CLOUDFLARENET", "AMAZON-02", "GOOGLE-CLOUD-PLATFORM").
var sharedInfraTokens = []string{
	"cloudflare", "fastly", "akamai", "amazon", "aws", "google", "microsoft",
	"azure", "digitalocean", "linode", "hetzner", "ovh", "cloudfront",
	"edgecast", "stackpath", "bunny", "vercel", "netlify", "oracle", "alibaba",
	"apple", "facebook", "meta", "cdn77", "limelight", "incapsula", "sucuri",
	"github", "gitlab", "leaseweb", "godaddy", "automattic",
}

// SharedInfrastructure reports whether an AS owner is a CDN or cloud provider.
func SharedInfrastructure(org string) bool {
	if org == "" {
		return false
	}
	o := strings.ToLower(org)
	for _, t := range sharedInfraTokens {
		if strings.Contains(o, t) {
			return true
		}
	}
	return false
}

// detectUnsignedOutbound fires when an unsigned program makes its first
// contact with a destination. Signature data is Windows-only; elsewhere Signed
// is false for everything, so the FirstContact gate keeps this quiet.
func detectUnsignedOutbound(s Subject, _ *Engine) map[string]any {
	if s.Event.Signed || s.Conn.Inbound || !s.FirstContact {
		return nil
	}
	if s.Event.Kind != event.KindNetConnect || s.Conn.Image == "" {
		return nil
	}
	return map[string]any{}
}

// detectForeignFirstContact fires on first contact with a network registered in
// a country the user's software has no other business in. Deliberately Medium
// severity in the pack: geography is a hint, not a verdict — plenty of
// legitimate services are hosted abroad.
func detectForeignFirstContact(s Subject, _ *Engine) map[string]any {
	if !s.FirstContact || s.Conn.Inbound || s.Recon.Country == "" {
		return nil
	}
	if !watchedCountry(s.Recon.Country) {
		return nil
	}
	return map[string]any{}
}

// watchedCountries are jurisdictions that warrant a look on first contact for a
// consumer endpoint. This is NOT a claim that traffic there is malicious; it is
// a prompt to check, and the rule that uses it says so plainly.
var watchedCountries = map[string]bool{
	"RU": true, "KP": true, "IR": true, "BY": true, "SY": true,
}

func watchedCountry(cc string) bool { return watchedCountries[cc] }
