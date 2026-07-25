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
