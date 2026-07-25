package graph

import (
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
)

func TestNetConnectLinksToProcess(t *testing.T) {
	g := New()
	proc := event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "browser.exe", Time: time.Now()}
	conn := event.NormalizedEvent{Seq: 2, Kind: event.KindNetConnect, PID: 100, RemoteIP: "1.2.3.4", RemotePort: 443, Time: time.Now()}
	pid := g.Ingest(proc)
	cid := g.Ingest(conn)
	if !g.Poset().IsCausallyBefore(pid, cid) {
		t.Fatal("connection should be causally after its process")
	}
}

func TestChildProcessLinksToParent(t *testing.T) {
	g := New()
	parent := g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "browser.exe"})
	child := g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 220, PPID: 100, Image: "invoice.exe"})
	if !g.Poset().IsCausallyBefore(parent, child) {
		t.Fatal("child process should be causally after parent")
	}
}

func TestProcExitClearsLineage(t *testing.T) {
	g := New()
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "a.exe"})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcExit, PID: 100})
	// A connection arriving after exit (PID reused before a new ProcStart) must
	// not link to the dead process node.
	cid := g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindNetConnect, PID: 100, RemoteIP: "1.2.3.4"})
	if len(g.Poset().CausalAncestors(cid)) != 0 {
		t.Fatal("connection after proc exit should have no causal ancestors")
	}
}
