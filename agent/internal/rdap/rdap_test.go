package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A real ARIN-shaped IP response, trimmed to the fields we decode.
const ipJSON = `{
 "objectClassName":"ip network","handle":"NET-93-184-216-0-1","name":"EDGECAST-NETBLK-03",
 "startAddress":"93.184.216.0","endAddress":"93.184.216.255","country":"US","port43":"whois.arin.net",
 "events":[{"eventAction":"registration","eventDate":"2012-06-22T00:00:00Z"},
           {"eventAction":"last changed","eventDate":"2024-01-03T00:00:00Z"}],
 "entities":[{"handle":"EXAMPLE","roles":["registrant"],
   "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Networks Inc"]]],
   "entities":[{"roles":["abuse"],
     "vcardArray":["vcard",[["fn",{},"text","Abuse Desk"],["email",{},"text","abuse@example.net"]]]}]}]}`

// A registrar-shaped domain response for a very new domain.
func domainJSON(registered string) string {
	return `{"objectClassName":"domain","ldhName":"payments-verify.test",
 "status":["client transfer prohibited"],
 "events":[{"eventAction":"registration","eventDate":"` + registered + `"},
           {"eventAction":"expiration","eventDate":"2027-01-01T00:00:00Z"}],
 "nameservers":[{"ldhName":"ns1.cheapdns.test"},{"ldhName":"ns2.cheapdns.test"}],
 "entities":[{"roles":["registrar"],
   "vcardArray":["vcard",[["fn",{},"text","Budget Registrar LLC"]]]}]}`
}

func serverFor(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestIPLookupExtractsOwnershipAndAbuse(t *testing.T) {
	srv := serverFor(ipJSON)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, err := c.Lookup(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Kind != "ip" {
		t.Errorf("kind = %q, want ip", reg.Kind)
	}
	if reg.Range != "93.184.216.0 – 93.184.216.255" {
		t.Errorf("range = %q", reg.Range)
	}
	if reg.Registrant != "Example Networks Inc" {
		t.Errorf("registrant = %q", reg.Registrant)
	}
	// The abuse contact is nested inside the registrant entity.
	if reg.Abuse != "abuse@example.net" {
		t.Errorf("abuse = %q, want the nested abuse email", reg.Abuse)
	}
	if reg.Country != "US" || reg.Source != "whois.arin.net" {
		t.Errorf("country/source = %q/%q", reg.Country, reg.Source)
	}
}

// Domain age is the strongest signal RDAP offers: infrastructure registered
// days ago and already receiving traffic is a well-known pattern.
func TestNewDomainIsCalledOut(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -9).Format(time.RFC3339)
	srv := serverFor(domainJSON(recent))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, err := c.Lookup(context.Background(), "payments-verify.test")
	if err != nil {
		t.Fatal(err)
	}
	if reg.AgeDays < 8 || reg.AgeDays > 10 {
		t.Errorf("ageDays = %d, want about 9", reg.AgeDays)
	}
	if !strings.Contains(reg.Note, "days ago") {
		t.Errorf("a nine-day-old domain should be called out, got %q", reg.Note)
	}
	if reg.Registrar != "Budget Registrar LLC" {
		t.Errorf("registrar = %q", reg.Registrar)
	}
	if len(reg.Nameservers) != 2 {
		t.Errorf("nameservers = %v", reg.Nameservers)
	}
}

func TestOldDomainIsNotAlarming(t *testing.T) {
	old := time.Now().AddDate(-12, 0, 0).Format(time.RFC3339)
	srv := serverFor(domainJSON(old))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, _ := c.Lookup(context.Background(), "established.test")
	if strings.Contains(reg.Note, "days ago") {
		t.Errorf("a twelve-year-old domain must not be described as new: %q", reg.Note)
	}
	if !strings.Contains(reg.Note, "ten years") {
		t.Errorf("note = %q", reg.Note)
	}
}

// Repeat clicks must not repeatedly announce the user's interest to a registry.
func TestResultsAreCached(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(ipJSON))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	for i := 0; i < 5; i++ {
		if _, err := c.Lookup(context.Background(), "93.184.216.34"); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 1 {
		t.Fatalf("registry was queried %d times for the same address, want 1", hits)
	}
}

func TestMissingRecordIsAClearError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	_, err := c.Lookup(context.Background(), "203.0.113.1")
	if err == nil || !strings.Contains(err.Error(), "no registration record") {
		t.Fatalf("expected a plain-English not-found error, got %v", err)
	}
}

// Manual: hits the real service. Skipped unless explicitly enabled, because
// tests must not make network calls by default.
func TestLiveLookupManual(t *testing.T) {
	if os.Getenv("NITEWATCH_LIVE_RDAP") == "" {
		t.Skip("set NITEWATCH_LIVE_RDAP=1 to query the real registry")
	}
	c := New()
	for _, q := range []string{"93.184.216.34", "example.com"} {
		reg, err := c.Lookup(context.Background(), q)
		if err != nil {
			t.Errorf("%s: %v", q, err)
			continue
		}
		t.Logf("%s -> name=%q registrant=%q registrar=%q country=%s age=%dd note=%q",
			q, reg.Name, reg.Registrant, reg.Registrar, reg.Country, reg.AgeDays, reg.Note)
	}
}

// The query lands in an outbound URL path, so it cannot be trusted merely
// because it arrived from our own dashboard.
func TestRejectsThingsThatAreNotAddressesOrDomains(t *testing.T) {
	c := New()
	c.BaseURL = "http://127.0.0.1:1" // must never be reached

	for _, bad := range []string{
		"", "   ",
		"example.com/../../admin",
		"example.com?x=1",
		"exa mple.com",
		"localhost",        // no dot, not a registrable name
		"127.0.0.1",        // loopback
		"192.168.1.1",      // private
		"10.0.0.5",         // private
		"169.254.1.1",      // link-local
		"100.100.1.1",      // carrier NAT / VPN mesh
		"fe80::1",          // link-local v6
		"http://evil.test", // a URL, not a name
	} {
		if _, err := c.Lookup(context.Background(), bad); err == nil {
			t.Errorf("%q should have been rejected before any request", bad)
		}
	}
}

// Registries commonly list an administrative contact before the holder. Against
// real ARIN data that meant a duty engineer's personal name was displayed as the
// owner of a CDN's address block.
func TestAdminContactIsNotShownAsTheOwner(t *testing.T) {
	const arinShaped = `{"objectClassName":"ip network","name":"EDGECAST-NETBLK-03",
 "startAddress":"93.184.216.0","endAddress":"93.184.216.255",
 "entities":[
  {"roles":["administrative","technical"],
   "vcardArray":["vcard",[["fn",{},"text","Derrick Sawyer"],["kind",{},"text","individual"]]]},
  {"roles":["registrant"],
   "vcardArray":["vcard",[["fn",{},"text","MNT-EDGECAST"]]]}]}`
	srv := serverFor(arinShaped)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, err := c.Lookup(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Registrant != "MNT-EDGECAST" {
		t.Errorf("registrant = %q, want the holder listed second", reg.Registrant)
	}
	if reg.Contact != "Derrick Sawyer" {
		t.Errorf("contact = %q, want the admin contact kept separately", reg.Contact)
	}
}
