// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

func loadEveryPack(t *testing.T) *rules.Set {
	t.Helper()
	entries, err := os.ReadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	var packs []*rules.Pack
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../rules", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		p, err := rules.LoadPack(data)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		packs = append(packs, p)
	}
	return rules.NewSet(packs...)
}

// A bare filename is not an identity. "Agent.exe" in Program Files\Battle.net
// is Blizzard's updater; "Agent.exe" in AppData is something that chose a
// reassuring name. Telling those apart is the entire question a user is being
// asked to answer, so every alert about a program must name it by full path.
func TestEveryConnectionAlertCarriesTheFullPath(t *testing.T) {
	const fullPath = `C:\Users\kevin\AppData\Roaming\SneakyDir\Agent.exe`
	e := New(loadEveryPack(t), nil)

	subj := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn:   ledger.Connection{Image: fullPath, PID: 4242, RemoteIP: "203.0.113.9", RemotePort: 443},
		Recon:  recon.Info{ASN: 64500, Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"},
		HadDNS: false, FirstContact: true,
	}

	dets := e.Evaluate(subj)
	if len(dets) == 0 {
		t.Fatal("expected this subject to trip at least one rule")
	}
	for _, d := range dets {
		// The evidence is what matters: the dashboard renders the full path in
		// its own box, from this field, on every alert. "Agent.exe" alone is not
		// an identity — the directory is most of the signal.
		if got, _ := d.Fields["ImagePath"].(string); got != fullPath {
			t.Errorf("%s: evidence ImagePath = %q, want the full path", d.Rule.ID, got)
		}
	}
}

// The rule prose must NOT repeat the path, because the dashboard already shows
// it in a dedicated box that also says whether the location is unusual. Every
// narrative used to end with "The program is: <path>", so the path appeared
// twice in a row on screen — noise in exactly the place a worried person is
// trying to read carefully.
func TestRuleProseDoesNotRepeatThePath(t *testing.T) {
	const fullPath = `C:\Users\kevin\AppData\Roaming\SneakyDir\Agent.exe`
	e := New(loadEveryPack(t), nil)

	subj := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn:   ledger.Connection{Image: fullPath, PID: 4242, RemoteIP: "203.0.113.9", RemotePort: 443},
		Recon:  recon.Info{ASN: 64500, Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"},
		HadDNS: false, FirstContact: true,
	}
	for _, d := range e.Evaluate(subj) {
		if strings.Contains(d.Rule.RenderNarrative(d.Fields), fullPath) {
			t.Errorf("%s: narrative repeats the path the UI already displays", d.Rule.ID)
		}
		for _, step := range d.Rule.RenderPlaybook(d.Fields) {
			// A step that only restates the path is not an instruction.
			if strings.HasPrefix(step, "Program: ") {
				t.Errorf("%s: playbook step %q just repeats the path box", d.Rule.ID, step)
			}
		}
	}
}

// Same requirement for file-activity alerts.
func TestFileAlertsNameTheFullPath(t *testing.T) {
	const fullPath = `C:\Users\kevin\Downloads\stealer.exe`
	e := New(loadEveryPack(t), nil)

	dets := e.EvaluateFile(FileSubject{
		PID: 77, Image: fullPath,
		Path: `C:\Users\kevin\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
	})
	if len(dets) == 0 {
		t.Fatal("expected a credential-theft detection")
	}
	for _, d := range dets {
		if got, _ := d.Fields["ImagePath"].(string); got != fullPath {
			t.Errorf("%s: evidence ImagePath = %q, want the full path", d.Rule.ID, got)
		}
		// As above: the path is carried in evidence and rendered once by the
		// dashboard's program box, which also flags an unusual location. Rule
		// prose repeating it put the same string on screen twice.
		if strings.Contains(d.Rule.RenderNarrative(d.Fields), fullPath) {
			t.Errorf("%s: narrative repeats the path the UI already displays", d.Rule.ID)
		}
	}
}
