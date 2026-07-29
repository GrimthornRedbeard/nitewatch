// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package notify

import (
	"errors"
	"testing"
	"time"
)

type fake struct {
	sent []Alert
	err  error
}

func (f *fake) Notify(a Alert) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, a)
	return nil
}

// Medium and low must never interrupt: they are worth knowing, not worth
// stopping for. Spending attention on them is what gets a tool muted.
func TestOnlyCriticalAndHighInterrupt(t *testing.T) {
	for _, sev := range []string{"critical", "high"} {
		if !ShouldInterrupt(sev) {
			t.Errorf("%s should interrupt", sev)
		}
	}
	for _, sev := range []string{"medium", "low", "", "bogus"} {
		if ShouldInterrupt(sev) {
			t.Errorf("%s must not interrupt", sev)
		}
	}
}

func TestPerRuleCooldownStopsRepeats(t *testing.T) {
	f := &fake{}
	g := NewGate(f)
	now := time.Now()

	if !g.Deliver("r1", Alert{Severity: "high", Title: "t"}, now) {
		t.Fatal("first notification should be delivered")
	}
	if g.Deliver("r1", Alert{Severity: "high", Title: "t"}, now.Add(time.Minute)) {
		t.Error("the same rule must not repeat within the cooldown")
	}
	// A different rule is a different finding and is allowed through.
	if !g.Deliver("r2", Alert{Severity: "high", Title: "t"}, now.Add(time.Minute)) {
		t.Error("a different rule should be delivered")
	}
	// After the cooldown the original rule may speak again.
	if !g.Deliver("r1", Alert{Severity: "high", Title: "t"}, now.Add(DefaultCooldown+time.Minute)) {
		t.Error("after the cooldown the rule should be delivered again")
	}
}

// A real incident produces many alerts at once. Twenty popups is
// indistinguishable from an attack on the user's attention.
func TestBurstLimitCapsSimultaneousAlerts(t *testing.T) {
	f := &fake{}
	g := NewGate(f)
	now := time.Now()

	delivered := 0
	for i := 0; i < 10; i++ {
		if g.Deliver(string(rune('a'+i)), Alert{Severity: "critical", Title: "t"}, now) {
			delivered++
		}
	}
	if delivered != 3 {
		t.Fatalf("burst limit should cap delivery at 3, got %d", delivered)
	}
	if len(f.sent) != 3 {
		t.Fatalf("notifier saw %d, want 3", len(f.sent))
	}
}

func TestNotifierFailureIsNotFatal(t *testing.T) {
	g := NewGate(&fake{err: errors.New("toast unavailable")})
	if g.Deliver("r1", Alert{Severity: "critical", Title: "t"}, time.Now()) {
		t.Error("a failed notification should report as not delivered")
	}
	// And must not panic or block — reaching here is the assertion.
}

func TestNilGateAndNilNotifierAreSafe(t *testing.T) {
	var g *Gate
	if g.Deliver("r", Alert{Severity: "critical"}, time.Now()) {
		t.Error("a nil gate should deliver nothing")
	}
	if NewGate(nil).Deliver("r", Alert{Severity: "critical"}, time.Now()) {
		t.Error("a nil notifier should deliver nothing")
	}
}
