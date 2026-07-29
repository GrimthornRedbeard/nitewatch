// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	gr "github.com/ShaneDolphin/gorapide"
	"github.com/threattape/nitewatch/agent/internal/event"
)

// WindowConfig bounds how large a single poset generation may grow before the
// window rotates to a fresh one.
type WindowConfig struct {
	MaxEvents int
}

// Window keeps poset memory bounded. GoRapide posets are add-only (no eviction),
// so instead of pruning we rotate: when the current generation exceeds
// MaxEvents, we start a fresh Graph and re-seed it with the currently-live
// processes so causal continuity (process -> its future connections) survives.
type Window struct {
	cfg   WindowConfig
	cur   *Graph
	count int
	live  map[uint32]event.NormalizedEvent // PID -> its ProcStart, for re-seeding
}

func NewWindow(cfg WindowConfig) *Window {
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 50000
	}
	return &Window{cfg: cfg, cur: New(), live: make(map[uint32]event.NormalizedEvent)}
}

// Current returns the live Graph generation.
func (w *Window) Current() *Graph { return w.cur }

// Ingest adds an event, rotating first if the current generation is full.
func (w *Window) Ingest(e event.NormalizedEvent) gr.EventID {
	if w.count >= w.cfg.MaxEvents {
		w.rotate()
	}

	switch e.Kind {
	case event.KindProcStart:
		w.live[e.PID] = e
	case event.KindProcExit:
		delete(w.live, e.PID)
	}

	id := w.cur.Ingest(e)
	w.count++
	return id
}

// rotate starts a fresh Graph and replays the live processes into it so that
// events arriving after the rotation still attribute to their process.
func (w *Window) rotate() {
	fresh := New()
	// Carry name resolutions forward. Dropping them made every connection
	// arriving just after a rotation look like a bare-address contact, which
	// is precisely what the "connected without looking it up" rule fires on —
	// the agent manufacturing its own false positives at a size boundary.
	fresh.SeedDNSAnswers(w.cur.DNSAnswers())
	for _, proc := range w.live {
		fresh.Ingest(proc)
	}
	w.cur = fresh
	w.count = len(w.live)
}
