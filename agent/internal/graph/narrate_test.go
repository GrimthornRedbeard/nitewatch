// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
)

// The step list is accurate and nearly useless to a non-analyst. The same facts
// as a sentence are the difference between evidence and an explanation.
func TestNarrateProducesAReadableStory(t *testing.T) {
	g := New()
	now := time.Now()

	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 500,
		Image: `C:\Windows\explorer.exe`, Time: now})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 900, PPID: 500,
		Image: `C:\Program Files\BraveSoftware\brave.exe`, Time: now.Add(time.Second)})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindDNSQuery, PID: 900,
		QueryName: "api.anthropic.com", Answers: []string{"160.79.104.10"}, Time: now.Add(2 * time.Second)})
	conn := g.Ingest(event.NormalizedEvent{Seq: 4, Kind: event.KindNetConnect, PID: 900,
		RemoteIP: "160.79.104.10", RemotePort: 443, Time: now.Add(3 * time.Second)})
	for i := 0; i < 12; i++ {
		g.Ingest(event.NormalizedEvent{Seq: uint64(10 + i), Kind: event.KindFileRead, PID: 900,
			Path: fmt.Sprintf(`C:\Users\k\Pictures\holiday\IMG_%02d.jpg`, i),
			Time: now.Add(time.Duration(4+i) * time.Second)})
	}

	story := g.StoryFor(conn)
	ctx := g.ContextFor(900)
	text := Narrate(story, ctx, Peer{
		IP: "160.79.104.10", Port: 443, Domain: "api.anthropic.com",
		Owner: "ANTHROPIC", Country: "US", BytesSent: 4 << 20, BytesRecv: 120 << 10,
	})
	t.Logf("narrative: %s", text)

	// Every element the reader needs, in one sentence they can act on.
	for _, want := range []string{
		"You started",                 // user launched it, and we can say so
		"brave.exe",                   // the program
		"explorer.exe",                // what started it
		"looked up api.anthropic.com", // it asked by name
		"ANTHROPIC",                   // who owns the far end
		"US",                          // where
		"4.0 MB",                      // what moved
		"read 12 files",               // what else it touched
		"holiday",                     // and where
	} {
		if !strings.Contains(text, want) {
			t.Errorf("narrative missing %q:\n%s", want, text)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(text), ".") {
		t.Errorf("narrative should read as prose, got: %s", text)
	}
}

// Claiming the user did something we did not observe is exactly the confident
// wrongness that makes people stop believing a security tool.
func TestNarrateDoesNotClaimUserActionItCannotSee(t *testing.T) {
	g := New()
	// A connection from a process whose start was never observed.
	conn := g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindNetConnect, PID: 1200,
		RemoteIP: "93.184.216.34", RemotePort: 443})

	text := Narrate(g.StoryFor(conn), g.ContextFor(1200),
		Peer{IP: "93.184.216.34", Port: 443, Owner: "EXAMPLE-AS"})
	t.Logf("narrative: %s", text)

	if strings.Contains(text, "You started") {
		t.Errorf("must not claim the user started a process we never saw start:\n%s", text)
	}
	if !strings.Contains(text, "already running") {
		t.Errorf("should say the program was already running:\n%s", text)
	}
	if !strings.Contains(text, "EXAMPLE-AS") {
		t.Errorf("should still name the owner:\n%s", text)
	}
}

// A script-launched process must not be described as something the user opened.
func TestNarrateDistinguishesScriptLaunch(t *testing.T) {
	g := New()
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 400,
		Image: `C:\Windows\System32\wscript.exe`})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 700, PPID: 400,
		Image: `C:\Users\k\AppData\Roaming\svc.exe`})
	conn := g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindNetConnect, PID: 700,
		RemoteIP: "203.0.113.9", RemotePort: 443})

	text := Narrate(g.StoryFor(conn), g.ContextFor(700), Peer{IP: "203.0.113.9", Port: 443})
	t.Logf("narrative: %s", text)

	if strings.Contains(text, "You started") {
		t.Errorf("a script launch is not the user opening something:\n%s", text)
	}
	if !strings.Contains(text, "wscript.exe") {
		t.Errorf("should name what actually started it:\n%s", text)
	}
}

// A connection with no lookup should not imply one happened.
func TestNarrateOmitsLookupWhenNoneObserved(t *testing.T) {
	g := New()
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 800, Image: `C:\a\app.exe`})
	conn := g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindNetConnect, PID: 800,
		RemoteIP: "203.0.113.9", RemotePort: 443})

	text := Narrate(g.StoryFor(conn), g.ContextFor(800), Peer{IP: "203.0.113.9", Port: 443})
	if strings.Contains(text, "looked up") {
		t.Errorf("no lookup was observed, so none should be claimed:\n%s", text)
	}
}
