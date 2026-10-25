// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package keystone

import (
	"encoding/json"
	"testing"
	"time"

	gr "github.com/ShaneDolphin/gorapide"
	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/graph"
	"github.com/threattape/nitewatch/agent/internal/ledger"
)

// storyFrom builds a real Story through the real graph, so these tests exercise
// what the collector actually stores rather than a hand-written approximation.
func storyFrom(t *testing.T, evs ...event.NormalizedEvent) string {
	t.Helper()
	g := graph.New()
	var last gr.EventID
	for _, e := range evs {
		last = g.Ingest(e)
	}
	b, err := json.Marshal(g.StoryFor(last))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func TestExportCarriesTheSpawnFromThePosetEdges(t *testing.T) {
	story := storyFrom(t,
		event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: `C:\Program Files\Office\winword.exe`},
		event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 220, PPID: 100, Image: `C:\Windows\powershell.exe`},
		event.NormalizedEvent{Seq: 3, Kind: event.KindDNSQuery, PID: 220, QueryName: "evil.example", Answers: []string{"198.51.100.7"}},
		event.NormalizedEvent{Seq: 4, Kind: event.KindNetConnect, PID: 220, RemoteIP: "198.51.100.7", RemotePort: 443},
	)
	ex := Build([]ledger.Connection{{
		ID: 7, PID: 220, Image: `C:\Windows\powershell.exe`, RemoteIP: "198.51.100.7",
		RemotePort: 443, Domain: "evil.example", Story: story,
	}}, "WKSTN-07", "0.1.8-pre (test)", now)

	if ex.Schema != Schema || ex.SrcHost != "WKSTN-07" {
		t.Fatalf("envelope = %+v", ex)
	}
	if len(ex.Flows) != 1 || ex.Flows[0] != (Flow{SrcHost: "WKSTN-07", Dst: "evil.example", Port: 443}) {
		t.Fatalf("flows = %+v", ex.Flows)
	}
	if len(ex.Events) != 1 {
		t.Fatalf("events = %+v", ex.Events)
	}
	ev := ex.Events[0]
	if ev.PID != 220 || ev.Image != `C:\Windows\powershell.exe` || ev.Dst != "evil.example" {
		t.Errorf("event = %+v", ev)
	}
	if ev.ParentPID == nil || *ev.ParentPID != 100 || ev.ParentImage == nil || *ev.ParentImage != `C:\Program Files\Office\winword.exe` {
		t.Errorf("parent not carried from the poset: %+v", ev)
	}
	if ev.UserSID != nil {
		t.Errorf("user_sid must be null — this agent does not collect it, got %q", *ev.UserSID)
	}
	if len(ex.Stories) != 1 || ex.Stories[0].ConnectionID != 7 {
		t.Fatalf("stories = %+v", ex.Stories)
	}
}

// The failure this guards against: a third program resolved the name, so its
// lineage sits in the chain BEFORE the dialer's ProcStart in Lamport order. A
// "previous ProcStart is the parent" reading would name the resolver.
func TestExportNeverNamesAParentThePosetDidNotRecord(t *testing.T) {
	story := storyFrom(t,
		// The resolver has its own lineage, whose root ties with the updater
		// in Lamport order: the shape that fools an order-based reading.
		event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 40, Image: `C:\Windows\services.exe`},
		event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 30, PPID: 40, Image: `C:\Tools\resolver.exe`},
		event.NormalizedEvent{Seq: 3, Kind: event.KindProcStart, PID: 20, Image: `C:\Tools\updater.exe`},
		event.NormalizedEvent{Seq: 4, Kind: event.KindDNSQuery, PID: 30, QueryName: "cdn.test", Answers: []string{"203.0.113.9"}},
		event.NormalizedEvent{Seq: 5, Kind: event.KindNetConnect, PID: 20, RemoteIP: "203.0.113.9", RemotePort: 443},
	)
	ex := Build([]ledger.Connection{{
		PID: 20, Image: `C:\Tools\updater.exe`, RemoteIP: "203.0.113.9", RemotePort: 443,
		Domain: "cdn.test", Story: story,
	}}, "h", "", now)
	if p := ex.Events[0].ParentPID; p != nil {
		t.Fatalf("updater has no recorded parent, export claims pid %d (%s)", *p, *ex.Events[0].ParentImage)
	}
}

// Stories recorded by builds before the schema existed have steps but no edges.
// They export, but with no parent rather than an inferred one.
func TestLegacyStoryExportsWithoutAGuessedParent(t *testing.T) {
	legacy := `{"steps":[{"kind":"ProcStart","source":"winword.exe","detail":"pid 100","lamport":1},` +
		`{"kind":"ProcStart","source":"powershell.exe","detail":"pid 220","lamport":2},` +
		`{"kind":"NetConnect","source":"","detail":"198.51.100.7:443","lamport":3}],"mermaid":"flowchart TD\n"}`
	ex := Build([]ledger.Connection{{PID: 220, Image: "powershell.exe", RemoteIP: "198.51.100.7", RemotePort: 443, Story: legacy}}, "h", "", now)
	if ex.Events[0].ParentPID != nil {
		t.Fatalf("legacy story produced a parent: %+v", ex.Events[0])
	}
	if len(ex.Stories) != 1 || string(ex.Stories[0].Story) != legacy {
		t.Fatalf("legacy story should pass through verbatim, got %+v", ex.Stories)
	}
	if ex.Flows[0].Dst != "198.51.100.7" {
		t.Errorf("no domain: dst must fall back to the address, got %q", ex.Flows[0].Dst)
	}
}

func TestExportLeavesOutInboundAndDeduplicates(t *testing.T) {
	conns := []ledger.Connection{
		{PID: 5, Image: "a.exe", RemoteIP: "192.0.2.1", RemotePort: 443, Domain: "x.test"},
		{PID: 5, Image: "a.exe", RemoteIP: "192.0.2.1", RemotePort: 443, Domain: "x.test"},
		{PID: 6, Image: "b.exe", RemoteIP: "192.0.2.1", RemotePort: 443, Domain: "x.test"},
		{PID: 7, Image: "sshd.exe", RemoteIP: "192.0.2.50", RemotePort: 50122, Inbound: true},
	}
	ex := Build(conns, "h", "", now)
	if len(ex.Flows) != 1 {
		t.Errorf("one destination, want one flow: %+v", ex.Flows)
	}
	if len(ex.Events) != 2 {
		t.Errorf("two programs reached it, want two events: %+v", ex.Events)
	}
	for _, f := range ex.Flows {
		if f.Dst == "192.0.2.50" {
			t.Errorf("an inbound peer was exported as egress: %+v", f)
		}
	}
}

// Keystone's parsers iterate these keys; null would crash them where [] does not.
func TestEmptyExportUsesEmptyListsNotNull(t *testing.T) {
	b, _ := json.Marshal(Build(nil, "h", "", now))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"flows", "events", "stories"} {
		if _, ok := m[k].([]any); !ok {
			t.Errorf("%s = %v, want []", k, m[k])
		}
	}
}

func TestOneCorruptStoryDoesNotSinkTheExport(t *testing.T) {
	ex := Build([]ledger.Connection{
		{ID: 1, PID: 5, Image: "a.exe", RemoteIP: "192.0.2.1", RemotePort: 443, Story: `{"steps":[`},
		{ID: 2, PID: 6, Image: "b.exe", RemoteIP: "192.0.2.2", RemotePort: 443, Story: `{"steps":[]}`},
	}, "h", "", now)
	if _, err := json.Marshal(ex); err != nil {
		t.Fatalf("export failed to marshal: %v", err)
	}
	if len(ex.Stories) != 1 || ex.Stories[0].ConnectionID != 2 || len(ex.Events) != 2 {
		t.Fatalf("want the corrupt story skipped and everything else kept: %+v", ex)
	}
}
