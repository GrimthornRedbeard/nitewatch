// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package resolve

import (
	"net"
	"testing"
)

// withNets builds a LocalNets from CIDR strings, bypassing interface discovery.
func withNets(t *testing.T, cidrs ...string) *LocalNets {
	t.Helper()
	l := &LocalNets{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", c, err)
		}
		l.nets = append(l.nets, n)
	}
	return l
}

func TestIsLocalRecognizesOwnIPv6Prefix(t *testing.T) {
	// The exact scenario from a live run: the ISP-delegated /64 is globally
	// routable, so IsPublic says true, yet every address in it is a LAN device.
	l := withNets(t, "2600:1700:13b0:2fc0::/64", "192.168.1.0/24")

	lanV6 := "2600:1700:13b0:2fc0:e0ce:6da5:adb1:a2e2"
	if !IsPublic(lanV6) {
		t.Fatal("precondition: the LAN v6 address is globally routable")
	}
	if !l.IsLocal(lanV6) {
		t.Fatal("address in our own /64 must be recognized as local")
	}
	if l.IsExternal(lanV6) {
		t.Fatal("LAN v6 address must not count as external traffic")
	}
}

func TestIsExternalKeepsRealInternetTraffic(t *testing.T) {
	l := withNets(t, "2600:1700:13b0:2fc0::/64", "192.168.1.0/24")

	for _, ip := range []string{"93.184.216.34", "2606:4700::6810:85e5", "8.8.8.8"} {
		if !l.IsExternal(ip) {
			t.Errorf("%s should be external", ip)
		}
	}
	for _, ip := range []string{"192.168.1.66", "127.0.0.1", "fe80::1", "2600:1700:13b0:2fc0::5"} {
		if l.IsExternal(ip) {
			t.Errorf("%s should NOT be external", ip)
		}
	}
}

func TestIsLocalHandlesJunk(t *testing.T) {
	l := withNets(t, "192.168.1.0/24")
	if l.IsLocal("not-an-ip") || l.IsLocal("") {
		t.Fatal("unparseable addresses are not local")
	}
}
