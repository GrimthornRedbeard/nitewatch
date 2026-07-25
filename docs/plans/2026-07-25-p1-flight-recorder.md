# NiteWatch P1 "Flight Recorder" Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship a usable, causally-enriched, process-attributed network flight recorder for Windows — every outbound connection logged with the process and resolved domain behind it, viewable in a localhost "Who's talking?" dashboard. No detections yet.

**Architecture:** One Go binary. A platform-abstracted **event source** feeds normalized events into a **collector** that builds a GoRapide causal poset (rolling window, since GoRapide posets are add-only) and writes a persistent **connection ledger** (SQLite, pure-Go/CGO-free). A localhost HTTP server exposes a JSON API consumed by a **SvelteKit dashboard**. Real ETW lives behind a `//go:build windows` tag; a replay/mock source (cross-platform) drives all tests so the whole thing is developable and testable on WSL2.

**Tech Stack:** Go 1.22+, `github.com/ShaneDolphin/gorapide` (MIT, zero-dep core), `modernc.org/sqlite` (pure-Go), `github.com/Microsoft/go-winio`/ETW lib (Windows only, chosen in Task 2), SvelteKit + Vite (dashboard), Go stdlib `net/http` + `embed`.

---

## Key Design Constraints (from the design doc — read `docs/plans/2026-07-24-nitewatch-design.md` first)

- **No kernel driver.** Userland ETW only.
- **Nothing leaves the machine.** The HTTP server binds `127.0.0.1` exclusively.
- **CGO-free build.** Keep the single-static-exe promise: `modernc.org/sqlite`, not `mattn/go-sqlite3`.
- **GoRapide posets are add-only** — there is no `Remove`/`Evict`. The rolling window is implemented by rotating to a fresh poset and re-seeding pinned process-lineage nodes (Task 6), NOT by deleting events.
- **Testability:** ETW cannot run on WSL2. Every component behind the `EventSource` interface is tested via the replay source. Real ETW gets a thin, Windows-only smoke test run manually in a VM.

---

## Repository Layout (target end state)

```
agent/
  go.mod                       module github.com/threattape/nitewatch/agent
  cmd/nitewatch/main.go        entrypoint: wires source→collector→server
  internal/event/event.go      NormalizedEvent type + kinds
  internal/source/source.go    EventSource interface
  internal/source/replay.go    JSONL replay source (cross-platform, test driver)
  internal/source/etw_windows.go   real ETW source (//go:build windows)
  internal/source/etw_stub.go      build stub (//go:build !windows)
  internal/graph/graph.go      GoRapide poset wrapper + causal wiring
  internal/graph/window.go     rolling-window manager
  internal/ledger/ledger.go    SQLite connection ledger
  internal/ledger/schema.sql   embedded DDL
  internal/api/server.go       localhost HTTP + JSON endpoints
  internal/api/dashboard/      embedded built SvelteKit assets (go:embed)
  testdata/traces/*.jsonl      recorded/synthetic event traces
dashboard/                     SvelteKit source (built into agent/internal/api/dashboard)
```

---

## Task 0: Module bootstrap + CI skeleton

**Files:**
- Create: `agent/go.mod`, `agent/cmd/nitewatch/main.go`
- Create: `.github/workflows/agent.yml`

**Step 1:** Initialize the module.
```bash
cd agent && go mod init github.com/threattape/nitewatch/agent
go get github.com/ShaneDolphin/gorapide@latest
go get modernc.org/sqlite@latest
```

**Step 2:** Minimal `main.go` that compiles and prints a version banner.
```go
package main

import "fmt"

var version = "0.1.0-dev"

func main() {
	fmt.Printf("NiteWatch agent %s\n", version)
}
```

**Step 3:** Verify build on the dev box (cross-compile check both targets).
```bash
go build ./... && GOOS=windows GOARCH=amd64 go build ./...
```
Expected: both succeed, no output.

**Step 4:** CI workflow — `go vet`, `go test ./...`, and a `GOOS=windows` build gate.
```yaml
name: agent
on: { push: {}, pull_request: {} }
jobs:
  test:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: agent } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go vet ./...
      - run: go test ./... -race
      - run: GOOS=windows GOARCH=amd64 go build ./...
```

**Step 5:** Commit.
```bash
git add agent .github && git commit -m "chore: bootstrap agent module + CI"
```

---

## Task 1: NormalizedEvent — the internal event vocabulary

The single event shape every source emits and the collector consumes. Decouples us from ETW's schema so tests use plain structs.

**Files:**
- Create: `agent/internal/event/event.go`
- Test: `agent/internal/event/event_test.go`

**Step 1: Write the failing test.**
```go
package event

import "testing"

func TestNormalizedEventStableKey(t *testing.T) {
	e := NormalizedEvent{Kind: KindNetConnect, PID: 1234, Seq: 7}
	if e.Kind != KindNetConnect {
		t.Fatalf("kind mismatch")
	}
	if got := e.String(); got == "" {
		t.Fatalf("String() should be non-empty")
	}
}
```

**Step 2: Run — expect FAIL** (`undefined: NormalizedEvent`).
```bash
go test ./internal/event/ -run TestNormalizedEventStableKey -v
```

**Step 3: Implement.**
```go
package event

import (
	"fmt"
	"time"
)

type Kind string

const (
	KindProcStart  Kind = "ProcStart"
	KindProcExit   Kind = "ProcExit"
	KindNetConnect Kind = "NetConnect"
	KindDNSQuery   Kind = "DNSQuery"
	KindFileWrite  Kind = "FileWrite"
)

// NormalizedEvent is the source-agnostic representation of one telemetry record.
// ETW, replay, and any future source all emit this shape.
type NormalizedEvent struct {
	Seq       uint64            // monotonic within a run; assigned by the source
	Kind      Kind
	Time      time.Time
	PID       uint32
	PPID      uint32            // ProcStart only
	Image     string            // full path to the acting process image
	// Network:
	RemoteIP   string
	RemotePort uint16
	Proto      string           // "TCP"/"UDP"
	// DNS:
	QueryName string            // domain queried (DNSQuery) 
	Answers   []string          // resolved IPs (DNSQuery)
	// File:
	Path      string            // FileWrite target
	Extra     map[string]string // signer, hash, etc. — filled opportunistically
}

func (e NormalizedEvent) String() string {
	return fmt.Sprintf("#%d %s pid=%d %s", e.Seq, e.Kind, e.PID, e.Image)
}
```

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/event && git commit -m "feat: NormalizedEvent internal vocabulary"
```

---

## Task 2: EventSource interface + JSONL replay source

The replay source reads a `.jsonl` file of NormalizedEvents and streams them on a channel. This is the test harness for EVERYTHING downstream and the fixture format the design doc's "record ETW once, replay forever" strategy needs.

**Decision to make and document in the commit:** pick the Windows ETW library in Task 8, NOT now — the interface must not leak ETW types. Candidates to evaluate then: `github.com/0xrawsec/golang-etw`, `github.com/bi-zone/etw`. Record the choice + rationale in the Task 8 commit body.

**Files:**
- Create: `agent/internal/source/source.go`, `agent/internal/source/replay.go`
- Create: `agent/testdata/traces/basic.jsonl`
- Test: `agent/internal/source/replay_test.go`

**Step 1: Write the failing test.**
```go
package source

import (
	"context"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/event"
)

func TestReplaySourceStreamsInOrder(t *testing.T) {
	src, err := NewReplaySource("../../testdata/traces/basic.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := src.Events(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	var kinds []event.Kind
	for e := range ch {
		seqs = append(seqs, e.Seq)
		kinds = append(kinds, e.Kind)
	}
	if len(seqs) != 4 {
		t.Fatalf("want 4 events, got %d", len(seqs))
	}
	if kinds[0] != event.KindProcStart || kinds[1] != event.KindDNSQuery {
		t.Fatalf("unexpected order: %v", kinds)
	}
}
```

**Step 2:** Create the fixture `agent/testdata/traces/basic.jsonl` — a browser downloads and runs something that phones home (one event per line):
```json
{"seq":1,"kind":"ProcStart","time":"2026-07-25T10:00:00Z","pid":100,"ppid":8,"image":"C:\\Program Files\\BrowserCo\\browser.exe"}
{"seq":2,"kind":"DNSQuery","time":"2026-07-25T10:00:01Z","pid":100,"image":"C:\\Program Files\\BrowserCo\\browser.exe","queryName":"cdn.example.net","answers":["93.184.216.34"]}
{"seq":3,"kind":"NetConnect","time":"2026-07-25T10:00:01Z","pid":100,"image":"C:\\Program Files\\BrowserCo\\browser.exe","remoteIP":"93.184.216.34","remotePort":443,"proto":"TCP"}
{"seq":4,"kind":"ProcStart","time":"2026-07-25T10:00:05Z","pid":220,"ppid":100,"image":"C:\\Users\\kevin\\Downloads\\invoice.exe"}
```

**Step 3: Implement `source.go` + `replay.go`.**
```go
// source.go
package source

import (
	"context"

	"github.com/threattape/nitewatch/agent/internal/event"
)

// EventSource is the single seam between telemetry acquisition and analysis.
// Implementations: replaySource (tests, any OS) and etwSource (//go:build windows).
type EventSource interface {
	Events(ctx context.Context) (<-chan event.NormalizedEvent, error)
	Close() error
}
```
```go
// replay.go
package source

import (
	"bufio"
	"context"
	"encoding/json"
	"os"

	"github.com/threattape/nitewatch/agent/internal/event"
)

type replaySource struct{ path string; f *os.File }

func NewReplaySource(path string) (EventSource, error) {
	return &replaySource{path: path}, nil
}

func (r *replaySource) Events(ctx context.Context) (<-chan event.NormalizedEvent, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return nil, err
	}
	r.f = f
	out := make(chan event.NormalizedEvent)
	go func() {
		defer close(out)
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var e event.NormalizedEvent
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				continue // skip malformed lines; a corrupt trace shouldn't crash
			}
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (r *replaySource) Close() error {
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}
```
Note: the JSON field tags — add lowercase tags to `NormalizedEvent` fields in Task 1 (`json:"seq"`, `json:"queryName"`, etc.). Go back and add them; re-run Task 1 test.

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/source agent/testdata && git commit -m "feat: EventSource interface + JSONL replay source"
```

---

## Task 3: Graph wrapper — normalized events → GoRapide poset with causal wiring

Wrap a GoRapide `Poset`. Maintain a live map of `PID → most-recent process-node EventID` so network/file/DNS events can be linked to the process that caused them, and `ProcStart` children link to parents. This is the "who caused what" wiring.

**Files:**
- Create: `agent/internal/graph/graph.go`
- Test: `agent/internal/graph/graph_test.go`

**Step 1: Write the failing test.**
```go
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
```

**Step 2: Run — expect FAIL.**

**Step 3: Implement.**
```go
package graph

import (
	gr "github.com/ShaneDolphin/gorapide"
	"github.com/threattape/nitewatch/agent/internal/event"
)

type Graph struct {
	p       *gr.Poset
	procNode map[uint32]gr.EventID // PID -> latest process node
}

func New() *Graph {
	return &Graph{p: gr.NewPoset(), procNode: make(map[uint32]gr.EventID)}
}

func (g *Graph) Poset() *gr.Poset { return g.p }

// Ingest adds one normalized event to the poset, wiring causal edges, and
// returns the new node's EventID.
func (g *Graph) Ingest(e event.NormalizedEvent) gr.EventID {
	ev := gr.NewEvent(string(e.Kind), e.Image, map[string]any{
		"pid": e.PID, "remoteIP": e.RemoteIP, "remotePort": e.RemotePort,
		"queryName": e.QueryName, "path": e.Path, "seq": e.Seq,
	})
	_ = g.p.AddEvent(ev)

	switch e.Kind {
	case event.KindProcStart:
		if e.PPID != 0 {
			if parent, ok := g.procNode[e.PPID]; ok {
				_ = g.p.AddCausal(parent, ev.ID)
			}
		}
		g.procNode[e.PID] = ev.ID
	default:
		if proc, ok := g.procNode[e.PID]; ok {
			_ = g.p.AddCausal(proc, ev.ID)
		}
	case event.KindProcExit:
		delete(g.procNode, e.PID)
	}
	return ev.ID
}
```

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/graph && git commit -m "feat: causal graph wiring over GoRapide poset"
```

---

## Task 4: DNS→IP resolution join (the netstat-can't-do-this bit)

Track recent `DNSQuery` answers so a subsequent `NetConnect` to one of those IPs can be annotated with the domain and causally linked to the resolution.

**Files:**
- Modify: `agent/internal/graph/graph.go`
- Test: `agent/internal/graph/graph_test.go`

**Step 1: Add the failing test.**
```go
func TestConnectionResolvesDomainFromDNS(t *testing.T) {
	g := New()
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "browser.exe"})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindDNSQuery, PID: 100, QueryName: "cdn.example.net", Answers: []string{"93.184.216.34"}})
	cid := g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindNetConnect, PID: 100, RemoteIP: "93.184.216.34", RemotePort: 443})
	if got := g.DomainFor(cid); got != "cdn.example.net" {
		t.Fatalf("want cdn.example.net, got %q", got)
	}
}
```

**Step 2: Run — expect FAIL.**

**Step 3: Implement:** add `dnsByIP map[string]string` and `connDomain map[gr.EventID]string` to `Graph`; on `KindDNSQuery`, record each answer IP→QueryName; on `KindNetConnect`, look up `RemoteIP`, store `connDomain[ev.ID]`, and if the DNS node exists add a causal edge from it. Add `func (g *Graph) DomainFor(id gr.EventID) string`. (Keep the DNS map bounded — most-recent-wins is fine for P1.)

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/graph && git commit -m "feat: join DNS resolutions to connections by IP"
```

---

## Task 5: Connection ledger (SQLite, CGO-free)

Persist every `NetConnect` as a ledger row, enriched with the domain from Task 4.

**Files:**
- Create: `agent/internal/ledger/ledger.go`, `agent/internal/ledger/schema.sql`
- Test: `agent/internal/ledger/ledger_test.go`

**Step 1: Write the failing test** (uses a temp DB file, pure-Go driver — runs on WSL2).
```go
package ledger

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordAndQueryConnections(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil { t.Fatal(err) }
	defer db.Close()

	err = db.RecordConnection(Connection{
		Time: time.Now(), PID: 100, Image: "browser.exe",
		RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "TCP", Domain: "cdn.example.net",
	})
	if err != nil { t.Fatal(err) }

	rows, err := db.RecentConnections(10)
	if err != nil { t.Fatal(err) }
	if len(rows) != 1 || rows[0].Domain != "cdn.example.net" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestIsNewDestination(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "t.db"))
	defer db.Close()
	c := Connection{Time: time.Now(), PID: 1, Image: "a.exe", RemoteIP: "1.1.1.1", Domain: "x.test"}
	if !db.IsNewDestination(c.Image, c.Domain) { t.Fatal("first sighting should be new") }
	_ = db.RecordConnection(c)
	if db.IsNewDestination(c.Image, c.Domain) { t.Fatal("second sighting should not be new") }
}
```

**Step 2: Run — expect FAIL.**

**Step 3: Implement.** `schema.sql` (embedded via `//go:embed`):
```sql
CREATE TABLE IF NOT EXISTS connections (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL,
	pid        INTEGER NOT NULL,
	image      TEXT NOT NULL,
	remote_ip  TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	proto      TEXT NOT NULL,
	domain     TEXT,
	verdict    TEXT NOT NULL DEFAULT 'clean'
);
CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_image_domain ON connections(image, domain);
```
`ledger.go`: `Open` runs the DDL; `RecordConnection` inserts; `RecentConnections(limit)` selects newest-first; `IsNewDestination(image, domain)` = `SELECT COUNT(*) ... WHERE image=? AND domain=?` is zero. Import driver as `_ "modernc.org/sqlite"`, `sql.Open("sqlite", path)`.

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/ledger && git commit -m "feat: SQLite connection ledger (CGO-free)"
```

---

## Task 6: Rolling-window manager

GoRapide posets are add-only, so bound memory by rotating posets. Keep the current `*Graph`; when it exceeds a size/age threshold, start a fresh one, re-seeding the `procNode` lineage map (the live processes) so causal continuity survives the rotation. Old posets are dropped (their alert-relevant subgraphs, in P2+, will already have been serialized).

**Files:**
- Create: `agent/internal/graph/window.go`
- Test: `agent/internal/graph/window_test.go`

**Step 1: Write the failing test.**
```go
func TestWindowRotatesButKeepsLiveProcesses(t *testing.T) {
	w := NewWindow(WindowConfig{MaxEvents: 3})
	w.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: "browser.exe"})
	for i := 0; i < 5; i++ {
		w.Ingest(event.NormalizedEvent{Seq: uint64(i + 2), Kind: event.KindNetConnect, PID: 100, RemoteIP: "1.2.3.4"})
	}
	// After rotation the live process 100 must still be linkable.
	cid := w.Ingest(event.NormalizedEvent{Seq: 99, Kind: event.KindNetConnect, PID: 100, RemoteIP: "5.6.7.8"})
	if w.Current().DomainFor(cid) == "__panic__" { /* smoke: no panic */ }
	if w.Current().Poset().Len() > 4 {
		t.Fatalf("window should have rotated; len=%d", w.Current().Poset().Len())
	}
}
```

**Step 2: Run — expect FAIL.**

**Step 3: Implement** `Window` wrapping a `*Graph`, counting ingested events; when `MaxEvents` exceeded, build a new `Graph` and replay the live `procNode` PIDs as fresh `ProcStart` seed nodes (store the last `NormalizedEvent` per live PID to reseed). Expose `Ingest`, `Current() *Graph`.

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/graph/window.go agent/internal/graph/window_test.go && git commit -m "feat: rolling-window poset rotation"
```

---

## Task 7: Collector — wire source → window + ledger

The orchestration loop: pull events off the source channel, ingest into the window, and for every `NetConnect` write a ledger row with the joined domain and a first-seen flag.

**Files:**
- Create: `agent/internal/collector/collector.go`
- Test: `agent/internal/collector/collector_test.go`

**Step 1: Write the failing test** — drive the collector with the replay source + a temp ledger; assert the ledger ends with the expected connection rows and that `invoice.exe`'s connection (if the fixture has one) is flagged new.
```go
func TestCollectorPopulatesLedgerFromReplay(t *testing.T) {
	led, _ := ledger.Open(filepath.Join(t.TempDir(), "c.db"))
	defer led.Close()
	src, _ := source.NewReplaySource("../../testdata/traces/basic.jsonl")
	c := New(src, led)
	if err := c.Run(context.Background()); err != nil { t.Fatal(err) }
	rows, _ := led.RecentConnections(10)
	if len(rows) != 1 { t.Fatalf("want 1 connection from basic.jsonl, got %d", len(rows)) }
	if rows[0].Domain != "cdn.example.net" { t.Fatalf("domain not joined: %+v", rows[0]) }
}
```

**Step 2: Run — expect FAIL.**

**Step 3: Implement** `Collector{src, window, ledger}`; `Run(ctx)` ranges the channel, calls `window.Ingest`, and on `KindNetConnect` looks up the domain via `window.Current().DomainFor(id)`, computes `IsNewDestination`, and calls `RecordConnection`.

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/collector && git commit -m "feat: collector wiring source→window→ledger"
```

---

## Task 8: Real ETW source (Windows-only) + build stub

Now implement the actual telemetry acquisition. **Evaluate `0xrawsec/golang-etw` vs `bi-zone/etw` here and record the choice + why in the commit body.** This code is `//go:build windows`; on non-Windows a stub returns an error so the tree still builds.

**Files:**
- Create: `agent/internal/source/etw_windows.go` (`//go:build windows`)
- Create: `agent/internal/source/etw_stub.go` (`//go:build !windows`)
- Manual test: `agent/internal/source/etw_windows_smoke_test.go` (`//go:build windows`)

**Step 1:** Stub first (keeps CI green):
```go
//go:build !windows
package source
import ("context"; "errors")
func NewETWSource() (EventSource, error) { return nil, errors.New("ETW is Windows-only") }
```

**Step 2:** Windows implementation subscribes to the providers from the design doc (`Microsoft-Windows-Kernel-Process`, `-Network`, `-DNS-Client`, `-File`), maps each ETW record into a `NormalizedEvent`, and streams on the channel. Assign `Seq` monotonically. Requires elevation (session needs admin).

**Step 3:** Cross-compile gate (already in CI) must pass:
```bash
GOOS=windows GOARCH=amd64 go build ./... && go build ./...
```

**Step 4:** Manual VM smoke test (documented, not in CI) — run elevated on a Windows VM, open a browser, confirm `NetConnect` + `DNSQuery` events flow and the ledger fills. Record the steps in `agent/internal/source/README.md`.

**Step 5: Commit.**
```bash
git add agent/internal/source && git commit -m "feat: Windows ETW source [+ chosen lib + rationale]"
```

---

## Task 9: Localhost JSON API

Expose the ledger over `127.0.0.1`-only HTTP. Endpoints: `GET /api/connections?limit=`, `GET /api/talkers` (top talkers rollup), `GET /api/new-destinations?since=`.

**Files:**
- Create: `agent/internal/api/server.go`
- Test: `agent/internal/api/server_test.go`

**Step 1: Write the failing test** using `httptest` — seed a ledger, hit `/api/connections`, assert JSON body + that the listener config binds loopback.
```go
func TestConnectionsEndpointReturnsJSON(t *testing.T) {
	led, _ := ledger.Open(filepath.Join(t.TempDir(), "a.db"))
	_ = led.RecordConnection(ledger.Connection{Time: time.Now(), Image: "b.exe", RemoteIP: "1.2.3.4", Domain: "x.test"})
	srv := New(led)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/connections?limit=5", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "x.test") {
		t.Fatalf("bad response: %d %s", rr.Code, rr.Body.String())
	}
}
```

**Step 2: Run — expect FAIL.**

**Step 3: Implement** `Server{ledger}` with `Handler() http.Handler` (a `*http.ServeMux`) and `ListenAndServe()` that binds **`127.0.0.1:8973`** explicitly (never `:8973`). JSON-encode ledger rows.

**Step 4: Run — expect PASS.**

**Step 5: Commit.**
```bash
git add agent/internal/api && git commit -m "feat: loopback-only JSON API over the ledger"
```

---

## Task 10: SvelteKit "Who's talking?" dashboard

Static SvelteKit app (adapter-static) built into the agent and served from `go:embed`. One page: searchable/filterable connection table + three rollup cards (top talkers, new-this-week, feed-flagged — the last is a placeholder until P2 feeds).

**Files:**
- Create: `dashboard/` (SvelteKit scaffold), `dashboard/src/routes/+page.svelte`
- Create: `agent/internal/api/dashboard/` (build output, embedded)
- Modify: `agent/internal/api/server.go` (serve embedded assets at `/`)

**Step 1:** Scaffold with adapter-static, `fetch('/api/connections')`, render a table (process, domain, IP:port, time) with a text filter box. Build config outputs to `agent/internal/api/dashboard`.

**Step 2:** `go:embed dashboard/*` in `server.go`; serve at `/`, fall through to API under `/api`.

**Step 3:** Smoke test via the `run` skill: `go run ./cmd/nitewatch --replay testdata/traces/basic.jsonl --serve`, open `http://127.0.0.1:8973`, confirm the row for `cdn.example.net` renders. (Playwright MCP per the portfolio `run` convention.)

**Step 4:** Add a `dashboard` build step to CI (`npm ci && npm run build`) so the embedded assets stay current.

**Step 5: Commit.**
```bash
git add dashboard agent/internal/api && git commit -m "feat: Who's-talking dashboard (embedded SvelteKit)"
```

---

## Task 11: Main wiring + run modes

Tie it together: `nitewatch --serve` (real ETW source on Windows) and `nitewatch --replay <file> --serve` (dev/demo, any OS). Graceful shutdown on SIGINT.

**Files:**
- Modify: `agent/cmd/nitewatch/main.go`

**Steps:** parse flags; pick source (`--replay` → replay, else `NewETWSource()`); construct ledger (default path under `%ProgramData%\NiteWatch\` on Windows, `./nitewatch.db` on dev); start collector goroutine + API server; block on signal; clean shutdown. Manual verification via the `run` skill in `--replay` mode on the dev box. Commit.

---

## Definition of Done (P1)

- `go test ./... -race` green; `GOOS=windows` build green in CI.
- `nitewatch --replay testdata/traces/basic.jsonl --serve` on the dev box shows the connection with its resolved domain in the dashboard (smoke test passes).
- Manual Windows-VM smoke: real browsing populates the ledger with process-attributed, domain-resolved connections.
- README updated: how to run in replay mode, how to run elevated on Windows.
- **Deliberately deferred to P2:** any detection/alerting, intel feeds, the `verdict` column beyond `clean`, response actions.

---

## Notes for the Executor

- Add lowercase JSON tags to every `NormalizedEvent` field (Task 1) — the replay fixtures depend on them.
- Never bind the HTTP server to anything but `127.0.0.1` — this is a hard privacy constraint, not a default.
- Keep the build CGO-free: only `modernc.org/sqlite`. If a dependency drags in CGO, stop and reconsider.
- ETW work can't be validated on WSL2 — that's expected. Lean on the replay source for all automated tests; the Windows path gets manual VM smoke tests only.
- Follow superpowers:test-driven-development for each task: red → green → commit.
