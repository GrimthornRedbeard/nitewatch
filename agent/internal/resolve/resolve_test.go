package resolve

import "testing"

func TestIsPublicFiltersLocalTraffic(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":                   true,
		"162.159.134.234":           true,
		"2606:4700::1111":           true,
		"127.0.0.1":                 false,
		"::1":                       false,
		"192.168.1.66":              false,
		"10.0.0.5":                  false,
		"172.16.0.1":                false,
		"fe80::f907:c770:be3a:a372": false,
		"100.64.0.1":                false,
		"0.0.0.0":                   false,
		"not-an-ip":                 false,
		"":                          false,
	}
	for ip, want := range cases {
		if got := IsPublic(ip); got != want {
			t.Errorf("IsPublic(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestLookupSkipsNonPublicAndNeverBlocks(t *testing.T) {
	r := New()
	if got := r.Lookup("127.0.0.1"); got != "" {
		t.Fatalf("loopback should not resolve, got %q", got)
	}
	if got := r.Lookup("192.168.1.1"); got != "" {
		t.Fatalf("private should not resolve, got %q", got)
	}
	// First call on a public IP must return immediately (async lookup).
	if got := r.Lookup("8.8.8.8"); got != "" {
		t.Fatalf("first lookup should return empty immediately, got %q", got)
	}
}

func TestCachedNameIsReturned(t *testing.T) {
	r := New()
	r.mu.Lock()
	r.cache["8.8.8.8"] = "dns.google"
	r.mu.Unlock()
	if got := r.Lookup("8.8.8.8"); got != "dns.google" {
		t.Fatalf("want cached name, got %q", got)
	}
}
