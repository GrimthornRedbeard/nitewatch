// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package notify delivers alerts to the user outside the dashboard.
//
// Interruption is a budget, not a feature. Every toast spends a little of the
// user's willingness to pay attention, and a tool that spends it carelessly
// gets muted — at which point it protects nobody. The severity gate below is
// therefore product-critical, not cosmetic.
package notify

import (
	"log"
	"sync"
	"time"
)

// Alert is the minimum a notifier needs.
type Alert struct {
	ID       int64
	Severity string
	Title    string
	Body     string
}

// Notifier delivers a user-visible notification.
type Notifier interface {
	Notify(a Alert) error
}

// Gate decides what interrupts and what waits to be found.
//
//	critical → interrupt: something is actively wrong
//	high     → interrupt: worth looking at now
//	medium   → tray/badge only: worth knowing, not worth stopping for
//	low      → tray/badge only
type Gate struct {
	mu sync.Mutex
	n  Notifier

	// lastByRule rate-limits per rule so one misbehaving detector cannot
	// produce a stream of popups.
	lastByRule map[string]time.Time
	// perRuleCooldown is how long a rule stays quiet after interrupting.
	perRuleCooldown time.Duration
	// burst caps total interruptions in a rolling window regardless of rule —
	// a genuine incident produces many alerts at once, and twenty popups is
	// indistinguishable from an attack on the user's attention.
	recent     []time.Time
	burstLimit int
	burstEvery time.Duration
}

// DefaultCooldown keeps a single rule from repeating quickly.
const DefaultCooldown = 10 * time.Minute

func NewGate(n Notifier) *Gate {
	return &Gate{
		n:               n,
		lastByRule:      map[string]time.Time{},
		perRuleCooldown: DefaultCooldown,
		burstLimit:      3,
		burstEvery:      5 * time.Minute,
	}
}

// ShouldInterrupt reports whether a severity warrants a popup at all.
func ShouldInterrupt(severity string) bool {
	return severity == "critical" || severity == "high"
}

// Deliver notifies the user if the alert warrants interruption and the rate
// limits allow it. Returns whether a notification was shown.
func (g *Gate) Deliver(ruleID string, a Alert, now time.Time) bool {
	if g == nil || g.n == nil || !ShouldInterrupt(a.Severity) {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if last, ok := g.lastByRule[ruleID]; ok && now.Sub(last) < g.perRuleCooldown {
		return false
	}

	// Drop burst entries that have aged out, then check the cap.
	kept := g.recent[:0]
	for _, t := range g.recent {
		if now.Sub(t) < g.burstEvery {
			kept = append(kept, t)
		}
	}
	g.recent = kept
	if len(g.recent) >= g.burstLimit {
		// Still record the rule so the cooldown applies once the burst clears.
		g.lastByRule[ruleID] = now
		return false
	}

	if err := g.n.Notify(a); err != nil {
		log.Printf("notify: %v", err)
		return false
	}
	g.lastByRule[ruleID] = now
	g.recent = append(g.recent, now)
	return true
}
