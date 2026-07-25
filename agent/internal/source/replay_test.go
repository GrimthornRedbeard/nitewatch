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
	defer src.Close()

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
	if seqs[0] != 1 || seqs[3] != 4 {
		t.Fatalf("unexpected seq ordering: %v", seqs)
	}
}
