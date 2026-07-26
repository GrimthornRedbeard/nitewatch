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
func TestEveryConnectionAlertNamesTheFullPath(t *testing.T) {
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
		text := d.Rule.RenderNarrative(d.Fields) + " " +
			strings.Join(d.Rule.RenderPlaybook(d.Fields), " ")
		if !strings.Contains(text, fullPath) {
			t.Errorf("%s: neither narrative nor playbook names the full path.\n%s",
				d.Rule.ID, text)
		}
		// The evidence must carry it too, so the UI can render it regardless of
		// what any individual rule's wording happens to say.
		if got, _ := d.Fields["ImagePath"].(string); got != fullPath {
			t.Errorf("%s: evidence ImagePath = %q, want the full path", d.Rule.ID, got)
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
		text := d.Rule.RenderNarrative(d.Fields) + " " +
			strings.Join(d.Rule.RenderPlaybook(d.Fields), " ")
		if !strings.Contains(text, fullPath) {
			t.Errorf("%s: does not name the full path.\n%s", d.Rule.ID, text)
		}
	}
}
