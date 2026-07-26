package graph

import (
	"strings"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/event"
)

// The whole reason GoRapide is a dependency: reconstructing WHY a connection
// happened. A flat log can say "invoice.exe contacted 1.2.3.4"; only the causal
// graph can say "the browser spawned invoice.exe, which resolved evil.test,
// which is where 1.2.3.4 came from".
func TestStoryReconstructsTheFullCausalChain(t *testing.T) {
	g := New()
	g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindProcStart, PID: 100, Image: `C:\Program Files\Browser\browser.exe`})
	g.Ingest(event.NormalizedEvent{Seq: 2, Kind: event.KindProcStart, PID: 220, PPID: 100, Image: `C:\Users\k\Downloads\invoice.exe`})
	g.Ingest(event.NormalizedEvent{Seq: 3, Kind: event.KindDNSQuery, PID: 220, Image: `C:\Users\k\Downloads\invoice.exe`,
		QueryName: "evil.test", Answers: []string{"185.4.3.2"}})
	conn := g.Ingest(event.NormalizedEvent{Seq: 4, Kind: event.KindNetConnect, PID: 220,
		Image: `C:\Users\k\Downloads\invoice.exe`, RemoteIP: "185.4.3.2", RemotePort: 443})

	story := g.StoryFor(conn)

	if len(story.Steps) != 4 {
		t.Fatalf("want 4 causal steps, got %d: %+v", len(story.Steps), story.Steps)
	}

	// Causal (Lamport) order, not arrival order.
	wantKinds := []string{"ProcStart", "ProcStart", "DNSQuery", "NetConnect"}
	for i, want := range wantKinds {
		if story.Steps[i].Kind != want {
			t.Errorf("step %d = %s, want %s", i, story.Steps[i].Kind, want)
		}
	}
	if story.Steps[0].Source != "browser.exe" {
		t.Errorf("chain should start at the browser, got %q", story.Steps[0].Source)
	}
	if story.Steps[2].Detail != "evil.test" {
		t.Errorf("DNS step should name the query, got %q", story.Steps[2].Detail)
	}
	if story.Steps[3].Detail != "185.4.3.2:443" {
		t.Errorf("connection step detail = %q", story.Steps[3].Detail)
	}

	// Lamport clocks must be non-decreasing along the chain.
	for i := 1; i < len(story.Steps); i++ {
		if story.Steps[i].Lamport < story.Steps[i-1].Lamport {
			t.Errorf("causal order violated at step %d: %d < %d",
				i, story.Steps[i].Lamport, story.Steps[i-1].Lamport)
		}
	}

	if !strings.HasPrefix(story.Mermaid, "flowchart TD") {
		t.Errorf("expected a Mermaid flowchart, got %q", story.Mermaid)
	}
	for _, want := range []string{"browser.exe", "invoice.exe", "evil.test", "185.4.3.2:443", "-->"} {
		if !strings.Contains(story.Mermaid, want) {
			t.Errorf("Mermaid missing %q:\n%s", want, story.Mermaid)
		}
	}
}

// A connection with no observed lineage still yields a one-step story rather
// than an error — common for processes already running when the agent starts.
func TestStoryForOrphanConnection(t *testing.T) {
	g := New()
	conn := g.Ingest(event.NormalizedEvent{Seq: 1, Kind: event.KindNetConnect, PID: 999, RemoteIP: "1.1.1.1", RemotePort: 443})
	story := g.StoryFor(conn)
	if len(story.Steps) != 1 || story.Steps[0].Kind != "NetConnect" {
		t.Fatalf("want a single NetConnect step, got %+v", story.Steps)
	}
}

func TestStoryForUnknownEventIsEmpty(t *testing.T) {
	g := New()
	if s := g.StoryFor("no-such-event"); len(s.Steps) != 0 || s.Mermaid != "" {
		t.Fatalf("unknown id should yield an empty story, got %+v", s)
	}
}
