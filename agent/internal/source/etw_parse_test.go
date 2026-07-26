package source

import (
	"reflect"
	"testing"
)

func TestParseDNSAnswers(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"bare v4", "93.184.216.34;", []string{"93.184.216.34"}},
		{"multiple", "93.184.216.34;93.184.216.35;", []string{"93.184.216.34", "93.184.216.35"}},
		{"v4-mapped v6 collapses", "::ffff:93.184.216.34;", []string{"93.184.216.34"}},
		{"real v6 preserved", "2606:4700::6810:85e5;", []string{"2606:4700::6810:85e5"}},
		{"cname mixed in is skipped", "cdn.example.net;93.184.216.34;", []string{"93.184.216.34"}},
		{"type tuple", "type: 1 93.184.216.34;", []string{"93.184.216.34"}},
		{"empty", "", nil},
		{"junk only", "somehost.example.com;", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseDNSAnswers(c.raw)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("parseDNSAnswers(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

func TestFormatHostPortBracketsIPv6(t *testing.T) {
	if got := FormatHostPort("192.168.1.1", 443); got != "192.168.1.1:443" {
		t.Fatalf("v4: got %q", got)
	}
	if got := FormatHostPort("2600:1700::1", 443); got != "[2600:1700::1]:443" {
		t.Fatalf("v6: got %q", got)
	}
	if got := FormatHostPort("10.0.0.1", 0); got != "10.0.0.1:0" {
		t.Fatalf("zero port: got %q", got)
	}
}
