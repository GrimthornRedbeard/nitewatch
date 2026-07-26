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
