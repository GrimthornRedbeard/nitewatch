package collector

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/source"
)

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
