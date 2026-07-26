package collector

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/source"
)

func TestCollectorSkipsLocalTrafficAndAttributesViaLookup(t *testing.T) {
	led, err := ledger.Open(filepath.Join(t.TempDir(), "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	src, err := source.NewReplaySource("../../testdata/traces/mixed_local.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	c := NewWithOptions(src, led, Options{
		// No ProcStart in this trace: attribution must come from the lookup,
		// exactly like a process that was already running before the agent.
		ImageLookup: func(pid uint32) string {
			if pid == 4242 {
				return `C:\Program Files\Thing\thing.exe`
			}
			return ""
		},
	})
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	rows, err := led.RecentConnections(50)
	if err != nil {
		t.Fatal(err)
	}
	// Only the public destination should be recorded; loopback/private/link-local dropped.
	if len(rows) != 1 {
		t.Fatalf("want 1 public connection, got %d: %+v", len(rows), rows)
	}
	if rows[0].RemoteIP != "93.184.216.34" {
		t.Fatalf("wrong connection recorded: %+v", rows[0])
	}
	if rows[0].Image == "" {
		t.Fatalf("connection should be attributed via ImageLookup, got empty image")
	}
}

func TestCollectorPopulatesLedgerFromReplay(t *testing.T) {
	led, err := ledger.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	src, err := source.NewReplaySource("../../testdata/traces/basic.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	c := New(src, led)
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	rows, err := led.RecentConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 connection from basic.jsonl, got %d", len(rows))
	}
	if rows[0].Domain != "cdn.example.net" {
		t.Fatalf("domain not joined through the graph: %+v", rows[0])
	}
	if rows[0].Image == "" || rows[0].RemoteIP != "93.184.216.34" {
		t.Fatalf("connection not attributed correctly: %+v", rows[0])
	}
}
