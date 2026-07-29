// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package rules loads detection rule packs.
//
// Rules are DATA, not code: a pack is YAML carrying a detector name, severity,
// and the hand-written narrative and playbook shown to the user. The advisory
// text is therefore deterministic — there is no model in the alert path,
// because wrong security advice delivered confidently is worse than no advice.
//
// NOT YET IMPLEMENTED, despite what the design doc anticipates:
//   - Packs are NOT signed. Shipped packs are embedded in the binary and so
//     inherit whatever integrity the executable has, but --rules loads
//     unsigned YAML from disk and is a development affordance, not a supported
//     update channel. Signature verification must land before packs are
//     distributed separately.
//   - Packs are NOT hot-loaded. They are read once at startup; changing a file
//     requires a restart.
//
// Both are recorded in docs/plans/ rather than implied here, because a comment
// describing a security property the code does not have is worse than silence.
package rules

import (
	"fmt"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Severity gates how loudly an alert interrupts the user.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

var severityRank = map[Severity]int{Low: 0, Medium: 1, High: 2, Critical: 3}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Rank orders severities for display and interruption decisions.
func (s Severity) Rank() int { return severityRank[s] }

// Area groups rules by the detection domain they belong to.
type Area string

const (
	AreaC2          Area = "c2"
	AreaPersistence Area = "persistence"
)

// Rule is one detection with its user-facing advisory.
type Rule struct {
	ID        string   `yaml:"id"`
	Area      Area     `yaml:"area"`
	Severity  Severity `yaml:"severity"`
	Detector  string   `yaml:"detector"`
	Title     string   `yaml:"title"`
	Narrative string   `yaml:"narrative"`
	Playbook  []string `yaml:"playbook"`

	// Compiled at load so a malformed template fails on startup rather than at
	// the moment we need to warn someone.
	titleTmpl     *template.Template
	narrativeTmpl *template.Template
	playbookTmpl  []*template.Template
}

// Pack is a set of rules loaded from one file.
type Pack struct {
	Name  string `yaml:"name"`
	Rules []Rule `yaml:"rules"`
}

// LoadPack parses and validates a YAML rule pack.
func LoadPack(data []byte) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse pack: %w", err)
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("pack %q contains no rules", p.Name)
	}

	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		switch {
		case strings.TrimSpace(r.ID) == "":
			return nil, fmt.Errorf("rule %d: missing id", i)
		case seen[r.ID]:
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		case !r.Severity.Valid():
			return nil, fmt.Errorf("rule %q: unknown severity %q", r.ID, r.Severity)
		case strings.TrimSpace(r.Detector) == "":
			return nil, fmt.Errorf("rule %q: missing detector", r.ID)
		case strings.TrimSpace(r.Title) == "":
			return nil, fmt.Errorf("rule %q: missing title", r.ID)
		case strings.TrimSpace(r.Narrative) == "":
			return nil, fmt.Errorf("rule %q: missing narrative", r.ID)
		}
		seen[r.ID] = true

		var err error
		if r.titleTmpl, err = template.New("t").Parse(r.Title); err != nil {
			return nil, fmt.Errorf("rule %q title template: %w", r.ID, err)
		}
		if r.narrativeTmpl, err = template.New("n").Parse(r.Narrative); err != nil {
			return nil, fmt.Errorf("rule %q narrative template: %w", r.ID, err)
		}
		r.playbookTmpl = nil
		for j, step := range r.Playbook {
			t, err := template.New("p").Parse(step)
			if err != nil {
				return nil, fmt.Errorf("rule %q playbook step %d: %w", r.ID, j, err)
			}
			r.playbookTmpl = append(r.playbookTmpl, t)
		}
	}
	return &p, nil
}

// RenderTitle fills the rule's headline from match data.
func (r *Rule) RenderTitle(data any) string { return render(r.titleTmpl, data) }

// RenderNarrative fills the plain-English explanation.
func (r *Rule) RenderNarrative(data any) string { return render(r.narrativeTmpl, data) }

// RenderPlaybook fills the "Do this..." steps.
func (r *Rule) RenderPlaybook(data any) []string {
	out := make([]string, 0, len(r.playbookTmpl))
	for _, t := range r.playbookTmpl {
		if s := strings.TrimSpace(render(t, data)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func render(t *template.Template, data any) string {
	if t == nil {
		return ""
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		// A template that fails at render time must not silence the alert —
		// the user still needs to know something happened.
		return ""
	}
	return b.String()
}

// Set is a collection of packs indexed by detector, so the engine can ask
// "which rules care about this detector?" once per event.
type Set struct {
	byDetector map[string][]*Rule
	all        []*Rule
}

// NewSet indexes packs for evaluation.
func NewSet(packs ...*Pack) *Set {
	s := &Set{byDetector: map[string][]*Rule{}}
	for _, p := range packs {
		for i := range p.Rules {
			r := &p.Rules[i]
			s.byDetector[r.Detector] = append(s.byDetector[r.Detector], r)
			s.all = append(s.all, r)
		}
	}
	// Highest severity first so the most serious rule for a detector wins.
	for _, rs := range s.byDetector {
		sort.SliceStable(rs, func(i, j int) bool {
			return rs[i].Severity.Rank() > rs[j].Severity.Rank()
		})
	}
	return s
}

// For returns the rules bound to a detector.
func (s *Set) For(detector string) []*Rule { return s.byDetector[detector] }

// All returns every loaded rule.
func (s *Set) All() []*Rule { return s.all }

// Len is the number of loaded rules.
func (s *Set) Len() int { return len(s.all) }
