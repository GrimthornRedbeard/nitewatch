package intel

import (
	"context"
	"os"
	"testing"
)

func TestLiveFeedsManual(t *testing.T) {
	if os.Getenv("NITEWATCH_LIVE_FEEDS") == "" {
		t.Skip("set NITEWATCH_LIVE_FEEDS=1 to fetch the real feeds")
	}
	s := New()
	dir := t.TempDir()
	if err := s.EnsureLoaded(context.Background(), dir, DefaultSources); err != nil {
		t.Fatal(err)
	}
	ips, domains := s.Count()
	t.Logf("loaded %d addresses, %d domains", ips, domains)
	if ips < 100 {
		t.Errorf("expected a substantial address set, got %d", ips)
	}
}
