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
