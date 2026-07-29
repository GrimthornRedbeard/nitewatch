// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import (
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

func detectionOf(sev rules.Severity, id string) Detection {
	return Detection{Rule: &rules.Rule{ID: id, Severity: sev}}
}

func subjectOf(image, signer string, signed bool, dest string) Subject {
	return Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect, Signed: signed, Signer: signer},
		Conn:   ledger.Connection{Image: image, RemoteIP: "203.0.113.7"},
		Domain: dest,
	}
}

// The single most important property: a Critical finding is NEVER suppressed.
// Being signed by Microsoft does not make contacting malware control
// infrastructure acceptable.
func TestCriticalIsNeverSuppressed(t *testing.T) {
	s := NewSuppressor()
	now := time.Now()
	subj := subjectOf(`C:\Windows\System32\svchost.exe`, "Microsoft Windows", true, "evil.test")
	s.Observe(subj.Conn.Image, now) // also inside the learning window

	v := s.Check(detectionOf(rules.Critical, "c2-feed-flagged-connection"), subj, now)
	if v.Suppressed {
		t.Fatalf("critical must never be suppressed, got reason %q", v.Reason)
	}
}

func TestTrustedSignerSuppressesLowAndMediumOnly(t *testing.T) {
	s := NewSuppressor()
	now := time.Now()
	subj := subjectOf(`C:\Program Files\Google\Chrome\chrome.exe`, "Google LLC", true, "some.host")

	for _, sev := range []rules.Severity{rules.Low, rules.Medium} {
		if v := s.Check(detectionOf(sev, "r"), subj, now); !v.Suppressed {
			t.Errorf("%s from a trusted signer should be suppressed", sev)
		}
	}
	// High findings still get through even for trusted publishers — a trusted
	// program behaving strangely is exactly what we must not hide.
	if v := s.Check(detectionOf(rules.High, "r"), subj, now); v.Suppressed {
		t.Errorf("high must not be suppressed by signer trust, got %q", v.Reason)
	}
}

func TestUnsignedAndUnknownPublishersAreNotTrusted(t *testing.T) {
	s := NewSuppressor()
	now := time.Now()

	// Right publisher name but NOT actually signed: must not be trusted.
	claimed := subjectOf(`C:\x\fake.exe`, "Microsoft Windows", false, "h")
	if v := s.Check(detectionOf(rules.Medium, "r"), claimed, now); v.Suppressed {
		t.Error("an unverified signature claim must not confer trust")
	}
	// Genuinely signed, unknown publisher.
	unknown := subjectOf(`C:\x\tool.exe`, "Some Small Vendor Ltd", true, "h")
	if v := s.Check(detectionOf(rules.Medium, "r"), unknown, now); v.Suppressed {
		t.Error("an unrecognised publisher must not be auto-trusted")
	}
}

func TestLearningWindowHoldsThenReleases(t *testing.T) {
	s := NewSuppressor()
	install := time.Now()
	subj := subjectOf(`C:\Program Files\NewApp\app.exe`, "", false, "updates.newapp.test")
	s.Observe(subj.Conn.Image, install)

	// Just installed: medium noise is expected setup behaviour.
	if v := s.Check(detectionOf(rules.Medium, "r"), subj, install.Add(time.Minute)); !v.Suppressed {
		t.Error("medium findings during install should be held")
	}
	// High findings are never held, even during install.
	if v := s.Check(detectionOf(rules.High, "r"), subj, install.Add(time.Minute)); v.Suppressed {
		t.Error("high must not be held by the learning window")
	}
	// After the window, the same behaviour is no longer excused.
	later := install.Add(DefaultLearningWindow + time.Minute)
	if v := s.Check(detectionOf(rules.Medium, "r"), subj, later); v.Suppressed {
		t.Errorf("after the learning window, medium should alert; got %q", v.Reason)
	}
}

// Allowing one destination must not silence the same rule everywhere.
func TestAllowIsScopedToRuleProgramAndDestination(t *testing.T) {
	s := NewSuppressor()
	now := time.Now()
	image := `C:\App\app.exe`

	s.Allow("r1", image, "known.test")

	allowed := subjectOf(image, "", false, "known.test")
	if v := s.Check(detectionOf(rules.High, "r1"), allowed, now); !v.Suppressed {
		t.Fatal("the allowed combination should be suppressed")
	}

	// Same rule and program, different destination.
	other := subjectOf(image, "", false, "brand-new.test")
	if v := s.Check(detectionOf(rules.High, "r1"), other, now); v.Suppressed {
		t.Error("allowing one destination must not silence others")
	}
	// Same program and destination, different rule.
	if v := s.Check(detectionOf(rules.High, "r2"), allowed, now); v.Suppressed {
		t.Error("allowing one rule must not silence other rules")
	}
	// Different program, same rule and destination.
	otherProg := subjectOf(`C:\Other\other.exe`, "", false, "known.test")
	if v := s.Check(detectionOf(rules.High, "r1"), otherProg, now); v.Suppressed {
		t.Error("allowing one program must not silence others")
	}
}

// An allow beats even a critical finding: the user was asked and answered, and
// nagging after an explicit decision is what gets a tool uninstalled.
func TestAllowOverridesCritical(t *testing.T) {
	s := NewSuppressor()
	subj := subjectOf(`C:\App\app.exe`, "", false, "known.test")
	s.Allow("c2-feed-flagged-connection", subj.Conn.Image, "known.test")
	if v := s.Check(detectionOf(rules.Critical, "c2-feed-flagged-connection"), subj, time.Now()); !v.Suppressed {
		t.Fatal("an explicit user allow should hold")
	}
}

func TestSuppressionAlwaysExplainsItself(t *testing.T) {
	s := NewSuppressor()
	now := time.Now()
	subj := subjectOf(`C:\Program Files\Google\Chrome\chrome.exe`, "Google LLC", true, "h")
	v := s.Check(detectionOf(rules.Low, "r"), subj, now)
	if !v.Suppressed || v.Reason == "" {
		t.Fatal("a suppressed detection must carry a reason; silent suppression hides detector failure")
	}
}

func TestTrustedSignerMatching(t *testing.T) {
	for _, s := range []string{"Microsoft Windows", "Microsoft Corporation", "Google LLC", "Valve Corp.", "  google   llc  "} {
		if !TrustedSigner(s) {
			t.Errorf("%q should be recognised as trusted", s)
		}
	}
	// Substring matching would let anyone reach the trust list by registering a
	// company whose name CONTAINS a trusted one, then buying a certificate for
	// it legitimately.
	for _, s := range []string{
		"", "Totally Legit Software Inc", "Micr0soft",
		"Intelligent Systems Ltd", // contains "intel"
		"Googleplex Media LLC",    // contains "google"
		"Microsoft Corporation Evil Branch",
		"Not Microsoft Corporation",
	} {
		if TrustedSigner(s) {
			t.Errorf("%q must not be treated as trusted", s)
		}
	}
}
