// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package rules

import (
	"strings"
	"testing"
)

const goodPack = `
name: test-c2
rules:
  - id: c2-feed-flagged-connection
    area: c2
    severity: critical
    detector: connection-intel-hit
    title: "{{.ProcessName}} is contacting a server flagged for malware control"
    narrative: |
      {{.ProcessName}} opened a connection to {{.Destination}}, which appears on the
      {{.FeedName}} threat-intelligence feed.
    playbook:
      - "Disconnect this device from the network if you did not expect this."
      - "Note the program: {{.ImagePath}}"
  - id: c2-raw-ip-no-dns
    area: c2
    severity: high
    detector: raw-ip-no-dns
    title: "{{.ProcessName}} connected to a bare address"
    narrative: "No lookup preceded this connection."
`

func TestLoadPackCompilesTemplates(t *testing.T) {
	p, err := LoadPack([]byte(goodPack))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(p.Rules))
	}

	data := map[string]string{
		"ProcessName": "invoice.exe",
		"Destination": "185.4.3.2:443",
		"FeedName":    "Feodo Tracker",
		"ImagePath":   `C:\Users\k\Downloads\invoice.exe`,
	}
	r := &p.Rules[0]
	if got := r.RenderTitle(data); !strings.Contains(got, "invoice.exe") {
		t.Errorf("title not filled: %q", got)
	}
	if got := r.RenderNarrative(data); !strings.Contains(got, "Feodo Tracker") {
		t.Errorf("narrative not filled: %q", got)
	}
	steps := r.RenderPlaybook(data)
	if len(steps) != 2 || !strings.Contains(steps[1], `Downloads\invoice.exe`) {
		t.Errorf("playbook not filled: %+v", steps)
	}
}

// A broken template must fail at load, not when someone needs the warning.
func TestBrokenTemplateFailsAtLoad(t *testing.T) {
	bad := `
name: broken
rules:
  - id: x
    area: c2
    severity: high
    detector: d
    title: "{{.Unclosed"
    narrative: "n"
`
	if _, err := LoadPack([]byte(bad)); err == nil {
		t.Fatal("expected a load error for a malformed template")
	}
}

func TestValidationRejectsBadPacks(t *testing.T) {
	cases := map[string]string{
		"unknown severity":  "name: p\nrules:\n  - {id: a, area: c2, severity: catastrophic, detector: d, title: t, narrative: n}\n",
		"missing id":        "name: p\nrules:\n  - {area: c2, severity: high, detector: d, title: t, narrative: n}\n",
		"missing detector":  "name: p\nrules:\n  - {id: a, area: c2, severity: high, title: t, narrative: n}\n",
		"missing narrative": "name: p\nrules:\n  - {id: a, area: c2, severity: high, detector: d, title: t}\n",
		"no rules":          "name: empty\nrules: []\n",
		"duplicate id":      "name: p\nrules:\n  - {id: a, area: c2, severity: high, detector: d, title: t, narrative: n}\n  - {id: a, area: c2, severity: low, detector: d, title: t, narrative: n}\n",
	}
	for name, src := range cases {
		if _, err := LoadPack([]byte(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSetIndexesByDetectorSeverityFirst(t *testing.T) {
	p, err := LoadPack([]byte(goodPack))
	if err != nil {
		t.Fatal(err)
	}
	extra, err := LoadPack([]byte(`
name: extra
rules:
  - id: low-dup
    area: c2
    severity: low
    detector: connection-intel-hit
    title: t
    narrative: n
`))
	if err != nil {
		t.Fatal(err)
	}

	s := NewSet(p, extra)
	if s.Len() != 3 {
		t.Fatalf("want 3 rules, got %d", s.Len())
	}
	hits := s.For("connection-intel-hit")
	if len(hits) != 2 {
		t.Fatalf("want 2 rules on that detector, got %d", len(hits))
	}
	if hits[0].Severity != Critical {
		t.Errorf("most severe rule should sort first, got %s", hits[0].Severity)
	}
	if len(s.For("no-such-detector")) != 0 {
		t.Error("unknown detector should yield no rules")
	}
}

func TestSeverityRanking(t *testing.T) {
	if !(Low.Rank() < Medium.Rank() && Medium.Rank() < High.Rank() && High.Rank() < Critical.Rank()) {
		t.Fatal("severity ordering is wrong")
	}
	if Severity("bogus").Valid() {
		t.Fatal("unknown severity must not validate")
	}
}
