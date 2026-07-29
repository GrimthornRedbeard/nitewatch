// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

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

// Reported from a live machine: clicking "who owns this?" on
// 39.224.186.35.bc.googleusercontent.com answered "no registration record
// found". Correct, and useless — nobody registered that hostname. Google
// registered googleusercontent.com, and the name itself is generated from the
// address, so the address record is the one that answers the question.
func TestGeneratedHostnameIsLookedUpByAddress(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/domain/") {
			w.WriteHeader(http.StatusNotFound) // no record for the hostname
			return
		}
		_, _ = w.Write([]byte(ipJSON))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, err := c.LookupBest(context.Background(),
		"39.224.186.35.bc.googleusercontent.com", "39.224.186.35")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || !strings.HasPrefix(asked[0], "/ip/") {
		t.Errorf("should have asked about the address directly, asked: %v", asked)
	}
	if reg.Query != "39.224.186.35.bc.googleusercontent.com" {
		t.Errorf("should report what the user clicked, got %q", reg.Query)
	}
	if !strings.Contains(reg.Substituted, "generated automatically") {
		t.Errorf("should explain the substitution, got %q", reg.Substituted)
	}
}

// An ordinary subdomain is reduced to the registered domain rather than
// reported as missing.
func TestSubdomainFallsBackToTheRegisteredDomain(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		_, _ = w.Write([]byte(domainJSON("2015-01-01T00:00:00Z")))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, err := c.LookupBest(context.Background(), "media-atl3-3.cdn.whatsapp.net", "31.13.66.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "/domain/whatsapp.net" {
		t.Errorf("should have asked for whatsapp.net, asked: %v", asked)
	}
	if !strings.Contains(reg.Substituted, "whatsapp.net") {
		t.Errorf("should say which domain it used, got %q", reg.Substituted)
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"39.224.186.35.bc.googleusercontent.com": "googleusercontent.com",
		"media-atl3-3.cdn.whatsapp.net":          "whatsapp.net",
		"example.com":                            "example.com",
		"a.b.example.co.uk":                      "example.co.uk",
		"api.anthropic.com":                      "anthropic.com",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksGeneratedFrom(t *testing.T) {
	yes := [][2]string{
		{"39.224.186.35.bc.googleusercontent.com", "39.224.186.35"},
		{"162-254-199-165.valve.net", "162.254.199.165"},
		{"ec2-3-91-2-7.compute-1.amazonaws.com", "3.91.2.7"},
	}
	for _, c := range yes {
		if !looksGeneratedFrom(c[0], c[1]) {
			t.Errorf("looksGeneratedFrom(%q, %q) = false, want true", c[0], c[1])
		}
	}
	no := [][2]string{
		{"api.anthropic.com", "160.79.104.10"},
		{"media-atl3-3.cdn.whatsapp.net", "31.13.66.1"},
		// A partial octet match must not count.
		{"1.example.com", "1.2.3.4"},
	}
	for _, c := range no {
		if looksGeneratedFrom(c[0], c[1]) {
			t.Errorf("looksGeneratedFrom(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

// A transient failure is not "no such registration". Falling back on one would
// present the address record as though it answered the question asked about
// the name — quietly, with no way for the reader to tell.
func TestTransientFailureDoesNotSilentlySubstitute(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/domain/") {
			w.WriteHeader(http.StatusTooManyRequests) // throttled, not absent
			return
		}
		_, _ = w.Write([]byte(ipJSON))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	_, err := c.LookupBest(context.Background(), "sub.example.org", "93.184.216.34")
	if err == nil {
		t.Fatal("a rate-limited lookup must surface as an error, not as somebody else's record")
	}
	if !strings.Contains(err.Error(), "rate-limiting") {
		t.Errorf("error should explain the rate limit, got: %v", err)
	}
	for _, p := range paths {
		if strings.HasPrefix(p, "/ip/") {
			t.Error("must not have fallen back to the address after a transient failure")
		}
	}
}

// A genuine 404 is an answer, and falling back to the address is the right
// thing to do with it.
func TestGenuineAbsenceDoesFallBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/domain/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(ipJSON))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL

	reg, err := c.LookupBest(context.Background(), "sub.example.org", "93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Kind != "ip" || !strings.Contains(reg.Substituted, "No registration exists") {
		t.Errorf("should have fallen back to the address with an explanation: %+v", reg)
	}
}
