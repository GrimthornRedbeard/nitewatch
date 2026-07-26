package recon

import (
	"context"
	"os"
	"testing"
	"time"
)

// Manual: downloads the real dataset and checks addresses observed in a live
// capture. Skipped unless NITEWATCH_LIVE_RECON=1 so CI stays offline.
func TestLiveDatasetManual(t *testing.T) {
	if os.Getenv("NITEWATCH_LIVE_RECON") == "" {
		t.Skip("set NITEWATCH_LIVE_RECON=1 to exercise the real dataset")
	}
	db := New()
	start := time.Now()
	if err := db.EnsureLoaded(context.Background(), "/tmp/recontest/ip2asn.tsv"); err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded in %v", time.Since(start).Round(time.Millisecond))

	for _, ip := range []string{
		"162.159.136.234", "2a03:2880:f37e:91:face:b00c:0:6206",
		"2607:6bc0::10", "34.16.211.209", "162.254.199.165",
		"77.88.55.60", "5.255.255.242",
	} {
		i := db.Lookup(ip)
		t.Logf("%-40s AS%-8d %-30s %s", ip, i.ASN, i.Org, i.Country)
		if !i.Known() {
			t.Errorf("no ownership data for %s", ip)
		}
	}
}
