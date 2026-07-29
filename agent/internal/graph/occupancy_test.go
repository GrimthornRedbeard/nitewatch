// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
)

var t0 = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

// The reported failure: three programs blamed for one file operation, two of
// them credited with writing into each other's directories. A PID is unique
// only among LIVE processes, so the question has to be "who held this number
// when the event happened", not "who holds it now".
func TestEventsAttributeToWhoeverHeldThePIDAtThatMoment(t *testing.T) {
	g := New()
	const pid = 7788

	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: pid,
		Image: `C:\Program Files\BraveSoftware\brave.exe`, StartKey: 111, Time: at(0)})
	braveWrite := g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindFileWrite, PID: pid,
		Path: `C:\Users\k\AppData\Local\BraveSoftware\cache\a.bin`, Time: at(1)})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindProcExit, PID: pid, Time: at(2)})

	// The same number, a different program, moments later.
	g.Ingest(event.NormalizedEvent{Seq: 4, Kind: event.KindProcStart, PID: pid,
		Image: `C:\Program Files\WindowsApps\Claude\claude.exe`, StartKey: 222, Time: at(3)})
	claudeWrite := g.Ingest(event.NormalizedEvent{Seq: 5, Kind: event.KindFileWrite, PID: pid,
		Path: `C:\Users\k\AppData\Roaming\Claude\Network\x.bin`, Time: at(4)})

	braveCtx := g.ContextAt(pid, at(1))
	claudeCtx := g.ContextAt(pid, at(4))

	if last(braveCtx.Lineage) != "brave.exe" {
		t.Errorf("at t+1 the PID belonged to Brave, got %v", braveCtx.Lineage)
	}
	if last(claudeCtx.Lineage) != "claude.exe" {
		t.Errorf("at t+4 the PID belonged to Claude, got %v", claudeCtx.Lineage)
	}
	for _, a := range braveCtx.Recent {
		if contains(a.Detail, `Roaming\Claude`) {
			t.Errorf("Claude's write attributed to Brave: %+v", a)
		}
	}
	for _, a := range claudeCtx.Recent {
		if contains(a.Detail, `BraveSoftware`) {
			t.Errorf("Brave's write attributed to Claude: %+v", a)
		}
	}
	_ = braveWrite
	_ = claudeWrite
}

// Exits are easy to drop under load. A start event is proof the previous tenure
// ended, so the timeline must repair itself without one.
func TestMissedExitDoesNotLeakActivityToTheNextProcess(t *testing.T) {
	g := New()
	const pid = 4242

	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: pid,
		Image: "first.exe", StartKey: 1, Time: at(0)})
	// No ProcExit at all.
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: pid,
		Image: "second.exe", StartKey: 2, Time: at(10)})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindNetConnect, PID: pid,
		RemoteIP: "203.0.113.9", Time: at(11)})

	if got := last(g.ContextAt(pid, at(11)).Lineage); got != "second.exe" {
		t.Errorf("after a missed exit the later process owns its own traffic, got %q", got)
	}
	// And the first process keeps its own history, bounded at the handover.
	if got := last(g.ContextAt(pid, at(1)).Lineage); got != "first.exe" {
		t.Errorf("the earlier tenure should still resolve, got %q", got)
	}
	for _, a := range g.ContextAt(pid, at(1)).Recent {
		if a.Kind == "NetConnect" {
			t.Errorf("traffic from after the handover leaked backwards: %+v", a)
		}
	}
}

// ETW delivers nothing in causal order. An event that arrives late must resolve
// by ITS OWN timestamp, not by whatever is current when it is processed.
func TestLateEventResolvesToTheProcessThatWasRunning(t *testing.T) {
	g := New()
	const pid = 999

	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: pid,
		Image: "old.exe", StartKey: 1, Time: at(0)})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcExit, PID: pid, Time: at(5)})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindProcStart, PID: pid,
		Image: "new.exe", StartKey: 2, Time: at(6)})

	// Delivered now, but it happened while old.exe was alive.
	g.Ingest(event.NormalizedEvent{Seq: 4, Kind: event.KindNetConnect, PID: pid,
		RemoteIP: "198.51.100.7", Time: at(2)})

	var found bool
	for _, a := range g.ContextAt(pid, at(2)).Recent {
		if a.Kind == "NetConnect" {
			found = true
		}
	}
	if !found {
		t.Error("the late event should belong to the process alive when it happened")
	}
	for _, a := range g.ContextAt(pid, at(7)).Recent {
		if a.Kind == "NetConnect" {
			t.Errorf("the late event was attributed to the new process: %+v", a)
		}
	}
}

// Two successive processes running the SAME executable are still two processes.
// The start key is what makes that distinguishable at all.
func TestSameExecutableTwiceIsTwoTenures(t *testing.T) {
	g := New()
	const pid = 555
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: pid,
		Image: "worker.exe", StartKey: 10, Time: at(0)})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcExit, PID: pid, Time: at(3)})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindProcStart, PID: pid,
		Image: "worker.exe", StartKey: 20, Time: at(4)})
	g.Ingest(event.NormalizedEvent{Seq: 4, Kind: event.KindFileWrite, PID: pid,
		Path: `C:\Users\k\Documents\second.txt`, Time: at(5)})

	for _, a := range g.ContextAt(pid, at(1)).Recent {
		if contains(a.Detail, "second.txt") {
			t.Errorf("the second run's work was attributed to the first: %+v", a)
		}
	}
}

// A repeated start for the SAME process — ETW replays these during a rundown —
// must not create a second tenure.
func TestDuplicateStartIsNotASecondTenure(t *testing.T) {
	tbl := procTable{}
	tbl.begin(7, occupant{key: 42, image: "a.exe", node: "n1", start: at(0)})
	tbl.begin(7, occupant{key: 42, image: "a.exe", node: "n1", start: at(0)})
	if n := len(tbl[7]); n != 1 {
		t.Errorf("got %d tenures for one process, want 1", n)
	}
	if o, _ := tbl.at(7, at(1)); !o.live() {
		t.Error("the process should still be live after its duplicate start")
	}
}

// Without a timestamp the only safe answer is a tenure still open. Falling back
// to the last closed one re-creates the original bug in miniature.
func TestNoTimestampNeverResolvesToAnExitedProcess(t *testing.T) {
	tbl := procTable{}
	tbl.begin(9, occupant{key: 1, image: "gone.exe", node: "n1", start: at(0)})
	tbl.end(9, at(1))
	if _, ok := tbl.at(9, time.Time{}); ok {
		t.Error("an exited process must not be returned when there is no time to check against")
	}
}

func last(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) &&
		(hay == needle || len(hay) > 0 && indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// A generation rotation rebuilds the poset from the live process set, so the
// occupancy table is rebuilt too. Tenures must come back with their ORIGINAL
// start times: if rotation restamped them to "now", every event already in
// flight would fall before the tenure that produced it.
func TestAttributionSurvivesRotation(t *testing.T) {
	base := time.Date(2026, 7, 27, 4, 0, 0, 0, time.UTC)

	w := NewWindow(WindowConfig{MaxEvents: 4}) // tiny: rotates almost immediately
	w.Ingest(event.NormalizedEvent{
		Kind: event.KindProcStart, PID: 700, Image: `C:\App\long-runner.exe`,
		StartKey: 5001, Time: base,
	})
	for i := 0; i < 6; i++ {
		w.Ingest(event.NormalizedEvent{
			Kind: event.KindProcStart, PID: uint32(900 + i),
			Image: `C:\App\churn.exe`, StartKey: uint64(6000 + i),
			Time: base.Add(time.Duration(i) * time.Second),
		})
		w.Ingest(event.NormalizedEvent{
			Kind: event.KindProcExit, PID: uint32(900 + i),
			Time: base.Add(time.Duration(i)*time.Second + 100*time.Millisecond),
		})
	}

	// An event from the long-lived process, timestamped back at its start —
	// which is now several generations in the past.
	if got := w.Current().ImageAt(700, base.Add(time.Second)); got != `C:\App\long-runner.exe` {
		t.Fatalf("lost attribution across rotation: got %q", got)
	}
	if got := w.Current().ImageAt(700, base); got != `C:\App\long-runner.exe` {
		t.Errorf("start-instant attribution lost: got %q", got)
	}
}
