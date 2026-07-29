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

// "Brave is writing a hundred files — what caused that?" is the question the
// causal graph exists to answer. A flat log can only say a write happened.
func TestContextExplainsAFileBurst(t *testing.T) {
	g := New()
	now := time.Now()

	// explorer.exe -> brave.exe: the shape of a user opening a program.
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 500,
		Image: `C:\Windows\explorer.exe`, Time: now})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 900, PPID: 500,
		Image: `C:\Program Files\BraveSoftware\brave.exe`, Time: now.Add(time.Second)})

	// It looked something up, connected, then touched many files in one folder.
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindDNSQuery, PID: 900,
		QueryName: "upload.example.com", Answers: []string{"93.184.216.34"}, Time: now.Add(2 * time.Second)})
	g.Ingest(event.NormalizedEvent{Seq: 4, Kind: event.KindNetConnect, PID: 900,
		RemoteIP: "93.184.216.34", RemotePort: 443, Time: now.Add(3 * time.Second)})
	for i := 0; i < 40; i++ {
		g.Ingest(event.NormalizedEvent{Seq: uint64(10 + i), Kind: event.KindFileRead, PID: 900,
			Path: fmt.Sprintf(`C:\Users\k\Pictures\holiday\IMG_%02d.jpg`, i),
			Time: now.Add(time.Duration(4+i) * time.Second)})
	}

	ctx := g.ContextFor(900)

	if ctx.LaunchedBy != "explorer.exe" {
		t.Errorf("LaunchedBy = %q, want explorer.exe", ctx.LaunchedBy)
	}
	if !ctx.UserLaunched {
		t.Error("a program started from the shell should read as user-launched")
	}
	chain := strings.Join(ctx.Lineage, " -> ")
	if !strings.Contains(chain, "explorer.exe") || !strings.Contains(chain, "brave.exe") {
		t.Errorf("lineage should show the chain, got %q", chain)
	}

	if len(ctx.Recent) == 0 {
		t.Fatal("recent activity should be summarised")
	}

	// Explanatory events lead. Forty file operations would otherwise crowd out
	// the single lookup and connection that explain WHY they happened, and
	// "it contacted this host, then touched your photos" is the useful sentence.
	if ctx.Recent[0].Kind != "DNSQuery" {
		t.Errorf("the lookup should lead the summary, got %s first", ctx.Recent[0].Kind)
	}
	if !strings.Contains(ctx.Recent[0].Detail, "upload.example.com") {
		t.Errorf("the lookup should name the host, got %q", ctx.Recent[0].Detail)
	}

	// File activity must still be present, grouped by folder and counted rather
	// than listed forty times.
	var files *Activity
	for i := range ctx.Recent {
		if ctx.Recent[i].Kind == "FileRead" {
			files = &ctx.Recent[i]
			break
		}
	}
	if files == nil {
		t.Fatal("the file burst itself should appear in context")
	}
	if files.Count != 40 {
		t.Errorf("file activity count = %d, want 40 collapsed into one entry", files.Count)
	}
	if !strings.Contains(files.Detail, "holiday") {
		t.Errorf("file activity should name the folder, got %q", files.Detail)
	}

	if s := ctx.Summary(); !strings.Contains(s, "explorer.exe") {
		t.Errorf("summary should name the launcher, got %q", s)
	}
}

// A program started by a script is a materially different situation from one
// the user opened, and the context must distinguish them.
func TestContextDistinguishesScriptLaunchedProcesses(t *testing.T) {
	g := New()
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 400,
		Image: `C:\Windows\System32\wscript.exe`})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 700, PPID: 400,
		Image: `C:\Users\k\AppData\Roaming\svc.exe`})

	ctx := g.ContextFor(700)
	if ctx.LaunchedBy != "wscript.exe" {
		t.Errorf("LaunchedBy = %q, want wscript.exe", ctx.LaunchedBy)
	}
	if ctx.UserLaunched {
		t.Error("a script host is not the user opening something")
	}
}

func TestContextForUnknownProcessIsEmpty(t *testing.T) {
	g := New()
	if ctx := g.ContextFor(9999); len(ctx.Lineage) != 0 || ctx.Summary() != "" {
		t.Fatalf("unknown process should yield empty context, got %+v", ctx)
	}
}

// Reported from a live machine: three programs blamed for one file operation,
// and two of them credited with writing into each other's directories —
// "brave.exe wrote files in AppData\Roaming\Claude" alongside "claude.exe
// wrote files in BraveSoftware\Brave-Browser".
//
// Both are Electron applications that spawn many short-lived children, so PIDs
// recycle fast. When a start or exit event is missed, the next occupant of a
// PID inherits the previous one's causal node and its activity is chained onto
// a stranger's history.
func TestPIDReuseDoesNotAttributeWorkToTheWrongProgram(t *testing.T) {
	g := New()
	const pid = 7788

	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: pid,
		Image: `C:\Program Files\BraveSoftware\brave.exe`})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindFileWrite, PID: pid,
		Image: `C:\Program Files\BraveSoftware\brave.exe`,
		Path:  `C:\Users\k\AppData\Local\BraveSoftware\cache\a.bin`})

	// The PID is now reused by a different program, and its exit was missed —
	// so no ProcExit and no ProcStart arrive. The only clue is the image on the
	// event itself.
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindFileWrite, PID: pid,
		Image: `C:\Program Files\WindowsApps\Claude\claude.exe`,
		Path:  `C:\Users\k\AppData\Roaming\Claude\Network\x.bin`})

	braveCtx := g.ContextFor(pid)
	for _, a := range braveCtx.Recent {
		if strings.Contains(a.Detail, `Roaming\Claude`) {
			t.Errorf("Claude's file write was attributed to Brave: %+v", a)
		}
	}
}

// The guard must not fire on the same program described two ways. ETW and a
// later lookup disagree about case and about how the volume is written, and
// treating those as different processes would discard good causal links.
func TestSameProgramWrittenDifferentlyIsNotTreatedAsReuse(t *testing.T) {
	g := New()
	const pid = 4242
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: pid,
		Image: `C:\Program Files\BraveSoftware\brave.exe`})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindFileWrite, PID: pid,
		Image: `c:\program files\bravesoftware\BRAVE.EXE`,
		Path:  `C:\Users\k\Documents\a.txt`})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindFileWrite, PID: pid,
		Image: `\Device\HarddiskVolume3\Program Files\BraveSoftware\brave.exe`,
		Path:  `C:\Users\k\Documents\b.txt`})

	ctx := g.ContextFor(pid)
	if len(ctx.Lineage) == 0 {
		t.Fatal("the process node was dropped — case and volume differences were treated as reuse")
	}
	var writes int
	for _, a := range ctx.Recent {
		if a.Kind == "FileWrite" {
			writes += a.Count
		}
	}
	if writes < 2 {
		t.Errorf("expected both writes attributed to Brave, got %d", writes)
	}
}
