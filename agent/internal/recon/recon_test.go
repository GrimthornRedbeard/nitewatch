// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package recon

import (
	"strings"
	"testing"
)

// Real-shaped rows from the ip2asn dataset, including the networks seen in a
// live capture (Cloudflare, Facebook, Anthropic's provider) plus a Russian
// allocation to prove country attribution.
const sample = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
162.159.128.0	162.159.255.255	13335	US	CLOUDFLARENET
5.45.192.0	5.45.223.255	13238	RU	YANDEX
34.16.0.0	34.16.255.255	396982	US	GOOGLE-CLOUD-PLATFORM
192.0.2.0	192.0.2.255	0	NONE	Not routed
2a03:2880::	2a03:2880:ffff:ffff:ffff:ffff:ffff:ffff	32934	US	FACEBOOK
2606:4700::	2606:4700:ffff:ffff:ffff:ffff:ffff:ffff	13335	US	CLOUDFLARENET
`

func loadSample(t *testing.T) *DB {
	t.Helper()
	d := New()
	if err := d.Load(strings.NewReader(sample)); err != nil {
		t.Fatal(err)
	}
	if !d.Loaded() {
		t.Fatal("db should report loaded")
	}
	return d
}

func TestLookupIPv4(t *testing.T) {
	d := loadSample(t)
	got := d.Lookup("162.159.136.234") // Discord's Cloudflare edge, from a live run
	if got.ASN != 13335 || got.Org != "CLOUDFLARENET" || got.Country != "US" {
		t.Fatalf("got %+v", got)
	}
}

func TestLookupIPv6(t *testing.T) {
	d := loadSample(t)
	got := d.Lookup("2a03:2880:f37e:91:face:b00c:0:6206") // Facebook edge
	if got.ASN != 32934 || got.Org != "FACEBOOK" || got.Country != "US" {
		t.Fatalf("got %+v", got)
	}
}

// The headline use case: surfacing that traffic lands in an unexpected country.
func TestLookupForeignAllocation(t *testing.T) {
	d := loadSample(t)
	got := d.Lookup("5.45.200.1")
	if got.Country != "RU" || got.Org != "YANDEX" {
		t.Fatalf("got %+v", got)
	}
}

func TestBoundariesAreInclusive(t *testing.T) {
	d := loadSample(t)
	for _, ip := range []string{"162.159.128.0", "162.159.255.255"} {
		if got := d.Lookup(ip); got.ASN != 13335 {
			t.Errorf("boundary %s not matched: %+v", ip, got)
		}
	}
	// Just outside the allocation.
	if got := d.Lookup("162.159.127.255"); got.Known() {
		t.Errorf("address below range should be unknown, got %+v", got)
	}
}

func TestUnknownAndUnroutedAreSilent(t *testing.T) {
	d := loadSample(t)
	for _, ip := range []string{"203.0.113.7", "192.0.2.5", "not-an-ip", ""} {
		if got := d.Lookup(ip); got.Known() {
			t.Errorf("%q should be unknown, got %+v", ip, got)
		}
	}
}

func TestEmptyDBIsUsable(t *testing.T) {
	d := New()
	if d.Loaded() {
		t.Fatal("fresh db should not be loaded")
	}
	if got := d.Lookup("1.0.0.1"); got.Known() {
		t.Fatalf("empty db must return zero Info, got %+v", got)
	}
}

func TestIPv4MappedIPv6ResolvesAsIPv4(t *testing.T) {
	d := loadSample(t)
	if got := d.Lookup("::ffff:162.159.136.234"); got.ASN != 13335 {
		t.Fatalf("v4-mapped address should resolve via the v4 table: %+v", got)
	}
}
