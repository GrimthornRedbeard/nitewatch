// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
)

// A metronome is visible through any amount of encryption. You cannot read the
// check-in, but you can see it happens every sixty seconds and has forty times.
func TestSteadyRhythmIsDetected(t *testing.T) {
	tr := NewBeaconTracker()
	start := time.Now()

	var got Beacon
	var fired bool
	for i := 0; i < 20; i++ {
		b, ok := tr.Observe("evil.exe|c2.test", start.Add(time.Duration(i)*60*time.Second))
		if ok {
			got, fired = b, true
			break
		}
	}
	if !fired {
		t.Fatal("a perfectly regular 60s check-in should be detected")
	}
	if d := got.Interval; d < 55*time.Second || d > 65*time.Second {
		t.Errorf("interval = %v, want about 60s", d)
	}
	if got.Samples < MinBeaconSamples {
		t.Errorf("samples = %d, want at least %d", got.Samples, MinBeaconSamples)
	}
}

// Real C2 adds jitter deliberately to defeat this test, so modest variation
// must still be caught.
func TestJitteredBeaconIsStillDetected(t *testing.T) {
	tr := NewBeaconTracker()
	rng := rand.New(rand.NewSource(1))
	at := time.Now()

	var fired bool
	for i := 0; i < 25; i++ {
		// 60s ± up to 10%: what a beacon with light jitter looks like.
		at = at.Add(time.Duration(float64(60*time.Second) * (0.9 + 0.2*rng.Float64())))
		if _, ok := tr.Observe("evil.exe|c2.test", at); ok {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("a beacon with light jitter should still be detected")
	}
}

// Humans and event-driven software produce uneven traffic. That unevenness is
// the whole distinction, so it must not trip the detector.
func TestIrregularHumanTrafficIsNotABeacon(t *testing.T) {
	tr := NewBeaconTracker()
	rng := rand.New(rand.NewSource(2))
	at := time.Now()

	for i := 0; i < 40; i++ {
		// Anywhere from 6 seconds to 5 minutes apart: browsing, not polling.
		at = at.Add(time.Duration(6+rng.Intn(294)) * time.Second)
		if _, ok := tr.Observe("brave.exe|news.test", at); ok {
			t.Fatal("irregular browsing must not be reported as a beacon")
		}
	}
}

// A burst of packets is one conversation, not a schedule.
func TestRapidChatterIsNotABeacon(t *testing.T) {
	tr := NewBeaconTracker()
	at := time.Now()
	for i := 0; i < 200; i++ {
		at = at.Add(50 * time.Millisecond)
		if _, ok := tr.Observe("app.exe|api.test", at); ok {
			t.Fatal("sub-second chatter must not be reported as a beacon")
		}
	}
}

// One steady beacon must not alert on every subsequent check-in forever.
func TestBeaconAlertsOnceNotRepeatedly(t *testing.T) {
	tr := NewBeaconTracker()
	at := time.Now()
	var alerts int
	for i := 0; i < 60; i++ {
		at = at.Add(60 * time.Second)
		if _, ok := tr.Observe("evil.exe|c2.test", at); ok {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("a continuing beacon should alert once, got %d", alerts)
	}
}

// Update checks, telemetry and push channels poll on timers by design. On
// shared infrastructure that regularity is the product working.
func TestBeaconRuleIgnoresSharedInfrastructure(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	at := time.Now()
	for i := 0; i < 30; i++ {
		at = at.Add(60 * time.Second)
		subj := Subject{
			Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true},
			Conn: ledger.Connection{PID: 10, Image: `C:\App\updater.exe`,
				RemoteIP: "151.101.54.49", RemotePort: 443, LastSeen: at},
			Recon:  recon.Info{Org: "FASTLY"},
			Domain: "updates.example", HadDNS: true,
		}
		if d := find(e.Evaluate(subj), "c2-beaconing"); d != nil {
			t.Fatal("polling a CDN on a timer is normal and must not alert")
		}
	}
}

func TestBeaconRuleFiresOnUnremarkableHosting(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	at := time.Now()
	var d *Detection
	for i := 0; i < 30 && d == nil; i++ {
		at = at.Add(60 * time.Second)
		d = find(e.Evaluate(Subject{
			Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true},
			Conn: ledger.Connection{PID: 11, Image: `C:\Users\k\AppData\svc.exe`,
				RemoteIP: "203.0.113.9", RemotePort: 443, LastSeen: at},
			Recon:  recon.Info{Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"},
			Domain: "c2.evil.test", HadDNS: true,
		}), "c2-beaconing")
	}
	if d == nil {
		t.Fatal("a metronome to unremarkable hosting should fire")
	}
	narrative := d.Rule.RenderNarrative(d.Fields)
	if !strings.Contains(narrative, "minutes") && !strings.Contains(narrative, "seconds") {
		t.Errorf("narrative should state the interval:\n%s", narrative)
	}
}

// Regression from a live desktop, verbatim from the report: the Claude
// Microsoft Store app checking in with api.anthropic.com every 6.8 seconds was
// reported as command-and-control, with the narrative "a fixed rhythm means
// something is asking for instructions on a schedule, which is how
// remote-control malware stays in touch with whoever installed it."
//
// Three things were wrong with firing here, and each alone should have stopped
// it: the binary is signed, 6.8s is heartbeat cadence rather than an implant's
// sleep interval, and the destination is the publisher's own API.
func TestSignedAppPollingItsVendorIsNotBeaconing(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	const image = `C:\Program Files\WindowsApps\Claude_1.24012.9.0_x64__pzs8sxrjxfjjc\app\claude.exe`

	base := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 40; i++ { // well past MinBeaconSamples, perfectly regular
		at := base.Add(time.Duration(float64(i)*6.8) * time.Second)
		subj := Subject{
			Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true, Signer: "Anthropic PBC"},
			Conn: ledger.Connection{Image: image, RemoteIP: "160.79.104.10",
				RemotePort: 443, LastSeen: at},
			Recon:  recon.Info{Org: "ANTHROPIC", Country: "US"},
			Domain: "api.anthropic.com", HadDNS: true,
		}
		if d := find(e.Evaluate(subj), "c2-beaconing"); d != nil {
			t.Fatalf("signed app polling its own vendor fired c2-beaconing on sample %d", i)
		}
	}
}

// The floor must not be so high that it hides a real implant. An unsigned
// binary from a temp directory on a steady two-minute schedule is the case the
// detector exists for.
func TestUnsignedImplantOnASlowScheduleStillFires(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	const image = `C:\Users\k\AppData\Local\Temp\sync-helper.exe`

	base := time.Now().Add(-2 * time.Hour)
	var fired bool
	for i := 0; i < 40; i++ {
		at := base.Add(time.Duration(i) * 2 * time.Minute)
		subj := Subject{
			Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: false},
			Conn: ledger.Connection{Image: image, RemoteIP: "45.137.22.184",
				RemotePort: 8443, LastSeen: at},
			Recon: recon.Info{Org: "HOSTKEY-AS", Country: "NL"},
		}
		if d := find(e.Evaluate(subj), "c2-beaconing"); d != nil {
			fired = true
			break
		}
	}
	if !fired {
		t.Error("a steady unsigned two-minute beacon must still be caught")
	}
}

// Sub-30s regularity is heartbeat cadence, not a schedule worth reporting —
// even when the binary is unsigned.
func TestFastPollingIsBelowTheFloor(t *testing.T) {
	e := New(loadShippedPack(t), nil)
	base := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 40; i++ {
		subj := Subject{
			Event: event.NormalizedEvent{Kind: event.KindNetConnect},
			Conn: ledger.Connection{Image: `C:\x\app.exe`, RemoteIP: "203.0.113.9",
				RemotePort: 443, LastSeen: base.Add(time.Duration(i*7) * time.Second)},
			Recon: recon.Info{Org: "EXAMPLE-AS"},
		}
		if d := find(e.Evaluate(subj), "c2-beaconing"); d != nil {
			t.Fatalf("7-second polling fired at sample %d; that is a heartbeat", i)
		}
	}
}
