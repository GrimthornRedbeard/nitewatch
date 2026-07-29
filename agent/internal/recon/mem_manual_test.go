// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package recon

import (
	"context"
	"os"
	"runtime"
	"testing"
)

func TestLiveMemoryManual(t *testing.T) {
	if os.Getenv("NITEWATCH_LIVE_RECON") == "" {
		t.Skip("manual")
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	db := New()
	if err := db.EnsureLoaded(context.Background(), "/tmp/recontest/ip2asn.tsv"); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(db) // must stay live or GC reclaims it before we measure
	t.Logf("heap before=%.1f MB after=%.1f MB (dataset ~%.1f MB)",
		float64(before.HeapAlloc)/1e6, float64(after.HeapAlloc)/1e6,
		float64(after.HeapAlloc)/1e6-float64(before.HeapAlloc)/1e6)
	fi, _ := os.Stat("/tmp/recontest/ip2asn.tsv")
	t.Logf("cache file on disk: %.1f MB", float64(fi.Size())/1e6)
}
