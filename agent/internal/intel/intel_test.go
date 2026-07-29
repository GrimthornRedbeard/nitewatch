// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package intel

import (
	"strings"
	"testing"
)

// Feodo Tracker ships "ip:port" rows with '#' comment headers.
const feodoSample = `# Feodo Tracker Botnet C2 IP Blocklist
# Last updated: 2026-07-26
185.4.3.2:443
91.240.118.17:8080
1.2.3.4
`

// URLhaus ships full URLs; only the host is an indicator.
const urlhausSample = `# URLhaus host list
http://evil.test/payload.bin
https://cdn.badness.example:8443/x
plain-bad.test
`

func loadBoth(t *testing.T) *Store {
	t.Helper()
	s := New()
	if err := s.LoadList(strings.NewReader(feodoSample), Source{
		Name: "feodo", Kind: KindIP, Confidence: Malicious, Reason: "botnet C2",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadList(strings.NewReader(urlhausSample), Source{
		Name: "urlhaus", Kind: KindDomain, Confidence: Malicious, Reason: "malware distribution",
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFlagIPStripsPortAndSkipsComments(t *testing.T) {
	s := loadBoth(t)
	m, ok := s.FlagIP("185.4.3.2")
	if !ok || m.Feed != "feodo" || m.Confidence != Malicious {
		t.Fatalf("expected a malicious hit, got %+v ok=%v", m, ok)
	}
	if _, ok := s.FlagIP("91.240.118.17"); !ok {
		t.Error("second entry should be loaded")
	}
	if _, ok := s.FlagIP("1.2.3.4"); !ok {
		t.Error("bare address (no port) should load")
	}
	if _, ok := s.FlagIP("8.8.8.8"); ok {
		t.Error("clean address must not match")
	}
	// A '#' header line must never become an indicator.
	if _, ok := s.FlagIP("# Feodo Tracker Botnet C2 IP Blocklist"); ok {
		t.Error("comment leaked into the dataset")
	}
}

func TestFlagDomainReducesURLsToHosts(t *testing.T) {
	s := loadBoth(t)
	if _, ok := s.FlagDomain("evil.test"); !ok {
		t.Error("host from a full URL should be indexed")
	}
	if _, ok := s.FlagDomain("cdn.badness.example"); !ok {
		t.Error("host with a port should be indexed without it")
	}
	if _, ok := s.FlagDomain("plain-bad.test"); !ok {
		t.Error("bare host should be indexed")
	}
	if _, ok := s.FlagDomain("good.test"); ok {
		t.Error("clean domain must not match")
	}
}

// A feed entry for a domain should also flag its subdomains — malware moves
// between hostnames under one registered domain constantly.
func TestFlagDomainMatchesSubdomains(t *testing.T) {
	s := loadBoth(t)
	if _, ok := s.FlagDomain("cdn.node7.evil.test"); !ok {
		t.Error("subdomain of a listed domain should match")
	}
	if _, ok := s.FlagDomain("EVIL.TEST."); !ok {
		t.Error("matching must be case- and trailing-dot-insensitive")
	}
}

// The dangerous failure mode: a malformed feed entry that is just a TLD would
// otherwise flag the entire internet.
func TestBareTLDNeverMatchesEverything(t *testing.T) {
	s := New()
	if err := s.LoadList(strings.NewReader("com\n"), Source{
		Name: "broken", Kind: KindDomain, Confidence: Malicious,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.FlagDomain("www.microsoft.com"); ok {
		t.Fatal("a bare-TLD feed entry must not flag unrelated domains")
	}
}

func TestContextFeedsAreDistinguishable(t *testing.T) {
	s := New()
	_ = s.LoadList(strings.NewReader("171.25.193.9\n"), Source{
		Name: "tor-exits", Kind: KindIP, Confidence: Context, Reason: "Tor exit node",
	})
	m, ok := s.FlagIP("171.25.193.9")
	if !ok || m.Confidence != Context {
		t.Fatalf("Tor exits must be context, not malicious: %+v", m)
	}
}

func TestEmptyStoreIsUsable(t *testing.T) {
	s := New()
	if s.Loaded() {
		t.Error("fresh store should be empty")
	}
	if _, ok := s.FlagIP("1.1.1.1"); ok {
		t.Error("empty store must not match")
	}
	if _, ok := s.FlagDomain("example.com"); ok {
		t.Error("empty store must not match")
	}
}

// Emerging Threats ships C2 addresses inside bracketed rule lists, not one per
// line. $HOME_NET placeholders and private ranges must never become indicators.
func TestSuricataRuleExtraction(t *testing.T) {
	const rule = `alert ip [1.2.3.4,5.6.7.8,192.168.1.1] any -> $HOME_NET any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; sid:2404000; rev:5555;)
# comment line 10.0.0.1
alert ip [9.9.9.9] any -> $HOME_NET any (msg:"group 2"; sid:2404002;)`
	s := New()
	if err := s.LoadList(strings.NewReader(rule), Source{
		Name: "et-botcc", Kind: KindSuricataRule, Confidence: Malicious, Reason: "C2",
	}); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"} {
		if _, ok := s.FlagIP(ip); !ok {
			t.Errorf("%s should be extracted from the rule", ip)
		}
	}
	// Private addresses inside rules are placeholders, never indicators.
	if _, ok := s.FlagIP("192.168.1.1"); ok {
		t.Error("private address must not become an indicator")
	}
	if _, ok := s.FlagIP("10.0.0.1"); ok {
		t.Error("comment lines must be skipped entirely")
	}
}

// Tor CollecTor exit lists carry both the relay's published Address and the
// ExitAddress traffic actually emerges from. Only the latter is the indicator.
func TestTorExitListUsesExitAddressOnly(t *testing.T) {
	const exitList = `@type tordnsel 1.0
ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E
Published 2026-07-26 01:00:00
LastStatus 2026-07-26 02:00:00
ExitAddress 171.25.193.9 2026-07-26 02:12:00
ExitNode AAAA1111
Address 5.5.5.5
ExitAddress 185.220.101.1 2026-07-26 02:15:00`
	s := New()
	if err := s.LoadList(strings.NewReader(exitList), Source{
		Name: "tor-exits", Kind: KindTorExitList, Confidence: Context, Reason: "Tor exit",
	}); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"171.25.193.9", "185.220.101.1"} {
		m, ok := s.FlagIP(ip)
		if !ok {
			t.Errorf("%s should be an exit address", ip)
		} else if m.Confidence != Context {
			t.Errorf("%s should be context confidence", ip)
		}
	}
	if _, ok := s.FlagIP("5.5.5.5"); ok {
		t.Error("a relay's published Address is not an exit address")
	}
}

// Regression (QA sweep): the extractor scanned the whole rule line, so an
// address appearing in msg: text or a reference URL became a CRITICAL-severity
// indicator. A documentation link containing 8.8.8.8 would have flagged every
// DNS query the user makes.
func TestSuricataExtractionIgnoresNonIndicatorFields(t *testing.T) {
	const rule = `alert ip [185.4.3.2] any -> $HOME_NET any (msg:"ET CNC seen contacting 8.8.8.8 relay"; reference:url,example.com/report?ip=1.1.1.1; sid:2404000;)`
	s := New()
	if err := s.LoadList(strings.NewReader(rule), Source{
		Name: "et-botcc", Kind: KindSuricataRule, Confidence: Malicious, Reason: "C2",
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.FlagIP("185.4.3.2"); !ok {
		t.Error("the bracketed indicator must still be extracted")
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if _, ok := s.FlagIP(ip); ok {
			t.Errorf("%s appears only in rule metadata and must NOT become an indicator", ip)
		}
	}
}
