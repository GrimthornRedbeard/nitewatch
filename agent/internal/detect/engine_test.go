package detect

import (
	"os"
	"strings"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

// loadShippedPack exercises the real c2.yaml, so a broken shipped rule fails
// the build rather than the user.
func loadShippedPack(t *testing.T) *rules.Set {
	t.Helper()
	data, err := os.ReadFile("../../rules/c2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := rules.LoadPack(data)
	if err != nil {
		t.Fatalf("shipped c2 pack does not load: %v", err)
	}
	return rules.NewSet(p)
}

func feedsWith(t *testing.T, list string, src intel.Source) *intel.Store {
	t.Helper()
	s := intel.New()
	if err := s.LoadList(strings.NewReader(list), src); err != nil {
		t.Fatal(err)
	}
	return s
}

func find(ds []Detection, id string) *Detection {
	for i := range ds {
		if ds[i].Rule.ID == id {
			return &ds[i]
		}
	}
	return nil
}

func TestIntelHitFiresCriticalWithFilledNarrative(t *testing.T) {
	feeds := feedsWith(t, "185.4.3.2\n", intel.Source{
		Name: "feodo", Kind: intel.KindIP, Confidence: intel.Malicious,
		Reason: "listed by abuse.ch Feodo Tracker as botnet command-and-control infrastructure",
	})
	e := New(loadShippedPack(t), feeds)

	got := e.Evaluate(Subject{
		Event: event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn: ledger.Connection{
			Image: `C:\Users\k\Downloads\invoice.exe`, RemoteIP: "185.4.3.2", RemotePort: 443,
		},
		HadDNS: true, FirstContact: true,
	})

	d := find(got, "c2-feed-flagged-connection")
	if d == nil {
		t.Fatalf("feed hit should fire; got %+v", got)
	}
	if d.Rule.Severity != rules.Critical {
		t.Errorf("severity = %s, want critical", d.Rule.Severity)
	}
	narrative := d.Rule.RenderNarrative(d.Fields)
	if !strings.Contains(narrative, "invoice.exe") || !strings.Contains(narrative, "Feodo Tracker") {
		t.Errorf("narrative not filled from match data:\n%s", narrative)
	}
	steps := d.Rule.RenderPlaybook(d.Fields)
	if len(steps) == 0 || !strings.Contains(strings.Join(steps, " "), `Downloads\invoice.exe`) {
		t.Errorf("playbook missing specifics: %+v", steps)
	}
}

// Context feeds must never fire an alert on their own.
func TestTorExitAloneDoesNotAlert(t *testing.T) {
	feeds := feedsWith(t, "171.25.193.9\n", intel.Source{
		Name: "tor-exits", Kind: intel.KindIP, Confidence: intel.Context, Reason: "Tor exit node",
	})
	e := New(loadShippedPack(t), feeds)
	got := e.Evaluate(Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true},
		Conn:   ledger.Connection{Image: `C:\App\app.exe`, RemoteIP: "171.25.193.9", RemotePort: 443},
		HadDNS: true, FirstContact: false,
	})
	if d := find(got, "c2-feed-flagged-connection"); d != nil {
		t.Fatal("a context-confidence feed must not raise a malware-control alert")
	}
}

func TestRawIPWithoutDNSFires(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	subj := Subject{
		// Unsigned: signed software dialling a bare address is how the modern
		// web works, and the rule no longer fires on it.
		Event: event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn:  ledger.Connection{Image: `C:\App\thing.exe`, RemoteIP: "203.0.113.9", RemotePort: 443},
		// Ownership data is required for this rule to be judgeable at all.
		Recon:  recon.Info{ASN: 64500, Org: "SOME-SMALL-HOSTING-LLC"},
		HadDNS: false, FirstContact: true,
	}
	if d := find(e.Evaluate(subj), "c2-raw-ip-no-dns"); d == nil {
		t.Fatal("raw-IP-with-no-lookup should fire")
	}

	// A connection that DID follow a lookup is normal.
	subj.HadDNS = true
	if d := find(e.Evaluate(subj), "c2-raw-ip-no-dns"); d != nil {
		t.Error("a connection preceded by DNS must not fire")
	}

	// Repeat traffic to a known destination must not re-fire.
	subj.HadDNS = false
	subj.FirstContact = false
	if d := find(e.Evaluate(subj), "c2-raw-ip-no-dns"); d != nil {
		t.Error("established destinations must not re-fire")
	}
}

func TestSignedProgramsDoNotTripUnsignedRule(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	base := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true, Signer: "Microsoft Windows"},
		Conn:   ledger.Connection{Image: `C:\Windows\System32\svchost.exe`, RemoteIP: "20.1.2.3", RemotePort: 443},
		HadDNS: true, FirstContact: true,
	}
	if d := find(e.Evaluate(base), "c2-unsigned-first-contact"); d != nil {
		t.Fatal("a signed program must not trip the unsigned rule")
	}
	base.Event.Signed = false
	if d := find(e.Evaluate(base), "c2-unsigned-first-contact"); d == nil {
		t.Fatal("an unsigned program's first contact should fire")
	}
}

func TestForeignFirstContactFiresOnlyOnFirstContact(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	subj := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true},
		Conn:   ledger.Connection{Image: `C:\App\chat.exe`, RemoteIP: "5.45.200.1", RemotePort: 443},
		Recon:  recon.Info{ASN: 13238, Org: "YANDEX", Country: "RU"},
		HadDNS: true, FirstContact: true,
	}
	d := find(e.Evaluate(subj), "c2-foreign-first-contact")
	if d == nil {
		t.Fatal("first contact with a watched country should fire")
	}
	if !strings.Contains(d.Rule.RenderTitle(d.Fields), "RU") {
		t.Error("title should name the country")
	}

	subj.FirstContact = false
	if d := find(e.Evaluate(subj), "c2-foreign-first-contact"); d != nil {
		t.Error("established foreign destinations must not re-fire")
	}

	// An unwatched country is not a signal at all.
	subj.FirstContact = true
	subj.Recon.Country = "US"
	if d := find(e.Evaluate(subj), "c2-foreign-first-contact"); d != nil {
		t.Error("ordinary countries must not fire")
	}
}

// The quiet-machine property: ordinary, signed, resolved, established traffic
// must produce nothing at all.
func TestNormalTrafficIsSilent(t *testing.T) {
	feeds := feedsWith(t, "185.4.3.2\n", intel.Source{
		Name: "feodo", Kind: intel.KindIP, Confidence: intel.Malicious,
	})
	e := New(loadShippedPack(t), feeds)
	got := e.Evaluate(Subject{
		Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true, Signer: "Google LLC"},
		Conn: ledger.Connection{
			Image:    `C:\Program Files\Google\Chrome\chrome.exe`,
			RemoteIP: "142.250.72.14", RemotePort: 443,
		},
		Recon:  recon.Info{ASN: 15169, Org: "GOOGLE", Country: "US"},
		Domain: "www.google.com",
		HadDNS: true, FirstContact: false,
	})
	if len(got) != 0 {
		for _, d := range got {
			t.Errorf("unexpected detection on normal traffic: %s", d.Rule.ID)
		}
	}
}

func TestNilIntelStoreDisablesFeedDetectorOnly(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	got := e.Evaluate(Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn:   ledger.Connection{Image: `C:\x\y.exe`, RemoteIP: "203.0.113.5", RemotePort: 443},
		Recon:  recon.Info{ASN: 64500, Org: "SOME-SMALL-HOSTING-LLC"},
		HadDNS: false, FirstContact: true,
	})
	if find(got, "c2-feed-flagged-connection") != nil {
		t.Error("no feeds loaded: the intel detector must stay silent")
	}
	if find(got, "c2-raw-ip-no-dns") == nil {
		t.Error("other detectors must still work without feeds")
	}
}

// Reported from a live machine: NiteWatch alerted on ITSELF downloading threat
// feeds from Fastly. Three causes, all fixed — this covers the rule itself.
//
// "No lookup was observed" is not "no lookup happened". DNS-over-HTTPS produces
// no DNS telemetry at all, and cached or configured addresses are resolved long
// before the connection. A bare-address contact to shared infrastructure is the
// normal shape of the modern web, not evidence of hiding.
func TestRawIPRuleIgnoresSharedInfrastructure(t *testing.T) {
	e := New(loadShippedPack(t), nil)

	cdn := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn:   ledger.Connection{Image: `C:\App\app.exe`, RemoteIP: "151.101.54.49", RemotePort: 443},
		Recon:  recon.Info{ASN: 54113, Org: "FASTLY", Country: "US"},
		HadDNS: false, FirstContact: true,
	}
	if d := find(e.Evaluate(cdn), "c2-raw-ip-no-dns"); d != nil {
		t.Error("a bare-address contact to a CDN is ordinary and must not alert")
	}

	// Same shape, but a network that is not shared hosting: still worth a look.
	obscure := cdn
	obscure.Conn.RemoteIP = "203.0.113.9"
	obscure.Recon = recon.Info{ASN: 64500, Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"}
	if d := find(e.Evaluate(obscure), "c2-raw-ip-no-dns"); d == nil {
		t.Error("a bare-address contact to unremarkable hosting should still fire")
	}

	// A destination we have a name for is identifiable, which is the opposite
	// of hiding — regardless of where the name came from.
	named := obscure
	named.Domain = "known.example"
	if d := find(e.Evaluate(named), "c2-raw-ip-no-dns"); d != nil {
		t.Error("a named destination must not fire the bare-address rule")
	}
}

func TestSharedInfrastructureRecognition(t *testing.T) {
	for _, org := range []string{"FASTLY", "CLOUDFLARENET", "AMAZON-02", "GOOGLE-CLOUD-PLATFORM", "AKAMAI-AS"} {
		if !SharedInfrastructure(org) {
			t.Errorf("%q should be recognised as shared infrastructure", org)
		}
	}
	for _, org := range []string{"", "SOME-SMALL-HOSTING-LLC", "YANDEX"} {
		if SharedInfrastructure(org) {
			t.Errorf("%q must not be treated as shared infrastructure", org)
		}
	}
}

// The CDN suppression depends on ownership data that downloads in the
// background. Firing before it loads would reproduce the very false positives
// the suppression exists to prevent — on every single restart.
func TestRawIPRuleStaysQuietWithoutOwnershipData(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	noRecon := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn:   ledger.Connection{Image: `C:\App\app.exe`, RemoteIP: "151.101.54.49", RemotePort: 443},
		HadDNS: false, FirstContact: true,
		// Recon deliberately zero: dataset not loaded yet.
	}
	if d := find(e.Evaluate(noRecon), "c2-raw-ip-no-dns"); d != nil {
		t.Fatal("without ownership data the signal cannot be judged and must not alert")
	}
}

// Regression from a live desktop: five HIGH alerts in one minute, all for
// signed mainstream software talking to its own vendor. The rule's premise —
// that a missing DNS lookup is suspicious — stopped holding once
// DNS-over-HTTPS became the browser default.
func TestRealWorldSignedVendorTrafficIsSilent(t *testing.T) {
	e := New(loadShippedPack(t), nil)

	// Verbatim from the report.
	cases := []struct {
		image, ip, org string
	}{
		{`C:\Program Files\Steam\steam.exe`, "162.254.199.165", "VALVE-CORPORATION"},
		{`C:\Program Files\Battle.net\Agent.exe`, "137.221.105.232", "BLIZZARD"},
		{`C:\Program Files\Google\Chrome\chrome.exe`, "160.79.104.10", "ANTHROPIC"},
		{`C:\Users\k\AppData\Local\Claude\claude.exe`, "2607:6bc0::10", "ANTHROPIC"},
		{`C:\Program Files\BraveSoftware\brave.exe`, "2620:10b:7001:11::128", "CONVIVA-AS"},
	}
	for _, c := range cases {
		subj := Subject{
			Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true, Signer: "Vendor"},
			Conn:  ledger.Connection{Image: c.image, RemoteIP: c.ip, RemotePort: 443},
			Recon: recon.Info{Org: c.org, Country: "US"},
			// Exactly the observed conditions: no lookup seen (DoH), first contact.
			HadDNS: false, FirstContact: true,
		}
		if d := find(e.Evaluate(subj), "c2-raw-ip-no-dns"); d != nil {
			t.Errorf("%s -> %s (%s): signed vendor traffic must not alert",
				c.image, c.ip, c.org)
		}
	}
}

// The case the rule still exists for: no publisher, unremarkable network.
func TestUnsignedBinaryDiallingBareAddressStillFires(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	subj := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect}, // unsigned
		Conn:   ledger.Connection{Image: `C:\Users\k\Downloads\invoice.exe`, RemoteIP: "203.0.113.9", RemotePort: 443},
		Recon:  recon.Info{Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"},
		HadDNS: false, FirstContact: true,
	}
	d := find(e.Evaluate(subj), "c2-raw-ip-no-dns")
	if d == nil {
		t.Fatal("an unsigned binary dialling a bare address should still be surfaced")
	}
	if d.Rule.Severity != rules.Medium {
		t.Errorf("severity = %s, want medium — this is a prompt, not a finding", d.Rule.Severity)
	}
}
