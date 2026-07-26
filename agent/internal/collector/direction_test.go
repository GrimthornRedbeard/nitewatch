package collector

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/resolve"
	"github.com/threattape/nitewatch/agent/internal/source"
)

// localNetsForTest pins the collector to a known LAN so the test doesn't depend
// on the host's real interfaces.
func localNetsForTest(t *testing.T, cidrs ...string) *resolve.LocalNets {
	t.Helper()
	l := &resolve.LocalNets{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		l.Add(n)
	}
	return l
}

// Reproduces the real-device defect: Windows reports addresses relative to the
// packet, so on inbound events the "destination" is the local machine. Recording
// it blindly logged the user's own address as the peer.
func TestPeerIsAlwaysTheRemoteEnd(t *testing.T) {
	led, err := ledger.Open(filepath.Join(t.TempDir(), "dir.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	src, err := source.NewReplaySource("../../testdata/traces/direction.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	c := NewWithOptions(src, led, Options{})
	c.localNets = localNetsForTest(t, "192.168.1.0/24")

	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	rows, err := led.RecentConnections(50)
	if err != nil {
		t.Fatal(err)
	}

	// Event 2 is LAN-to-LAN and must be dropped entirely. Events 1 and 3 have a
	// genuine external peer, which must be the non-local end in both directions.
	if len(rows) != 2 {
		t.Fatalf("want 2 external connections, got %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.RemoteIP == "192.168.1.66" {
			t.Fatalf("recorded our OWN address as the peer: %+v", r)
		}
	}

	byIP := map[string]ledger.Connection{}
	for _, r := range rows {
		byIP[r.RemoteIP] = r
	}
	out, ok := byIP["162.159.136.234"]
	if !ok {
		t.Fatalf("outbound peer missing: %+v", rows)
	}
	if out.RemotePort != 443 || out.Inbound {
		t.Fatalf("outbound flow wrong: %+v", out)
	}
	in, ok := byIP["93.184.216.34"]
	if !ok {
		t.Fatalf("inbound peer missing (source end should be the peer): %+v", rows)
	}
	if in.RemotePort != 443 {
		t.Fatalf("inbound peer port should be the remote's port, got %d", in.RemotePort)
	}
	if !in.Inbound {
		t.Fatalf("flow arriving at us should be marked inbound: %+v", in)
	}
}
