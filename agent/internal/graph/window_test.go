// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"testing"

	"github.com/threattape/nitewatch/agent/internal/event"
)

func TestWindowRotatesButKeepsLiveProcesses(t *testing.T) {
	w := NewWindow(WindowConfig{MaxEvents: 3})
	w.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "browser.exe"})
	for i := 0; i < 5; i++ {
		w.Ingest(event.NormalizedEvent{Seq: uint64(i + 2), Kind: event.KindNetConnect, PID: 100, RemoteIP: "1.2.3.4"})
	}

	// The window must have rotated to stay bounded.
	if got := w.Current().Poset().Len(); got > 4 {
		t.Fatalf("window should have rotated; poset len=%d", got)
	}

	// Process 100 survives rotation, so a later connection still links to it.
	cid := w.Ingest(event.NormalizedEvent{Seq: 99, Kind: event.KindNetConnect, PID: 100, RemoteIP: "5.6.7.8"})
	if len(w.Current().Poset().CausalAncestors(cid)) == 0 {
		t.Fatal("post-rotation connection should still link to the surviving process")
	}
}

func TestWindowDoesNotRotateUnderThreshold(t *testing.T) {
	w := NewWindow(WindowConfig{MaxEvents: 100})
	for i := 0; i < 5; i++ {
		w.Ingest(event.NormalizedEvent{Seq: uint64(i), Kind: event.KindProcStart, PID: uint32(i), Image: "p.exe"})
	}
	if got := w.Current().Poset().Len(); got != 5 {
		t.Fatalf("no rotation expected; poset len=%d", got)
	}
}

// Rotation used to discard the DNS map, so a connection arriving just after a
// window boundary looked like a bare-address contact even though the program
// had resolved the name — the agent manufacturing its own false positives.
func TestRotationCarriesDNSResolutionsForward(t *testing.T) {
	w := NewWindow(WindowConfig{MaxEvents: 3})
	w.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "app.exe"})
	w.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindDNSQuery, PID: 100,
		QueryName: "cdn.example.net", Answers: []string{"93.184.216.34"}})

	// Force rotation past the resolution.
	for i := 0; i < 6; i++ {
		w.Ingest(event.NormalizedEvent{Seq: uint64(10 + i), Kind: event.KindNetConnect,
			PID: 100, RemoteIP: "10.0.0.1"})
	}

	id := w.Ingest(event.NormalizedEvent{Seq: 99, Kind: event.KindNetConnect,
		PID: 100, RemoteIP: "93.184.216.34", RemotePort: 443})
	if got := w.Current().DomainFor(id); got != "cdn.example.net" {
		t.Fatalf("resolution lost across rotation: DomainFor = %q, want cdn.example.net", got)
	}
}
