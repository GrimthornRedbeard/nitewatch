// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
)

// The graph has to be able to answer "did this process actually speak SSH?",
// because that is the difference between a client and a thief and it is the
// only place that knowledge lives.
func TestSSHPeersAtSeesOnlyPort22(t *testing.T) {
	base := time.Date(2026, 8, 4, 7, 29, 0, 0, time.UTC)
	g := New()
	g.Ingest(event.NormalizedEvent{
		Kind: event.KindProcStart, PID: 4242, Image: `C:\App\claude.exe`,
		StartKey: 99, Time: base,
	})
	// One SSH session, one ordinary HTTPS call, one repeat of the SSH host.
	for _, c := range []struct {
		ip   string
		port uint16
		at   int
	}{
		{"192.168.1.69", 22, 1},
		{"160.79.104.10", 443, 2},
		{"192.168.1.69", 22, 3},
		{"203.0.113.7", 22, 4},
	} {
		g.Ingest(event.NormalizedEvent{
			Kind: event.KindNetConnect, PID: 4242, Image: `C:\App\claude.exe`,
			RemoteIP: c.ip, RemotePort: c.port, Proto: "TCP",
			Time: base.Add(time.Duration(c.at) * time.Second),
		})
	}

	peers := g.SSHPeersAt(4242, base.Add(5*time.Second))
	if len(peers) != 2 {
		t.Fatalf("SSHPeersAt = %v, want the two port-22 hosts and not the 443 one", peers)
	}
	seen := map[string]bool{}
	for _, p := range peers {
		seen[p] = true
	}
	if !seen["192.168.1.69"] || !seen["203.0.113.7"] {
		t.Errorf("wrong hosts: %v", peers)
	}
	if seen["160.79.104.10"] {
		t.Error("an HTTPS destination was counted as an SSH peer")
	}
}

// A process that never spoke SSH must report none, or every credential read
// would quietly qualify for the downgrade.
func TestSSHPeersAtIsEmptyWithoutSSH(t *testing.T) {
	base := time.Date(2026, 8, 4, 7, 29, 0, 0, time.UTC)
	g := New()
	g.Ingest(event.NormalizedEvent{
		Kind: event.KindProcStart, PID: 7180, Image: `C:\Temp\thief.exe`,
		StartKey: 5, Time: base,
	})
	g.Ingest(event.NormalizedEvent{
		Kind: event.KindNetConnect, PID: 7180, Image: `C:\Temp\thief.exe`,
		RemoteIP: "45.137.22.184", RemotePort: 8443, Proto: "TCP",
		Time: base.Add(time.Second),
	})
	if peers := g.SSHPeersAt(7180, base.Add(2*time.Second)); len(peers) != 0 {
		t.Errorf("SSHPeersAt = %v, want none", peers)
	}
}
