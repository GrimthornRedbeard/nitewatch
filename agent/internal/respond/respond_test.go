package respond

import "testing"

func evidence(kv map[string]any) map[string]any { return kv }

// The safest effective option must be the obvious click.
func TestSuggestionsOrderLeastDestructiveFirst(t *testing.T) {
	acts := Suggest("c2", "critical", evidence(map[string]any{
		"ImagePath":   `C:\Users\k\Downloads\invoice.exe`,
		"ProcessName": "invoice.exe", "PID": "220",
		"RemoteIP": "185.4.3.2", "Destination": "185.4.3.2",
	}))
	if len(acts) != 3 {
		t.Fatalf("want block, kill and quarantine; got %d: %+v", len(acts), acts)
	}
	want := []Kind{BlockAddress, KillProcess, QuarantineFile}
	for i, k := range want {
		if acts[i].Kind != k {
			t.Errorf("position %d = %s, want %s", i, acts[i].Kind, k)
		}
	}
}

// Quarantine touches the disk, so it is offered only when we are confident.
func TestQuarantineOnlyOfferedForCritical(t *testing.T) {
	ev := map[string]any{"ImagePath": `C:\x\y.exe`, "ProcessName": "y.exe", "PID": "5", "RemoteIP": "1.2.3.4"}
	for _, sev := range []string{"high", "medium", "low"} {
		for _, a := range Suggest("c2", sev, ev) {
			if a.Kind == QuarantineFile {
				t.Errorf("%s severity must not offer quarantine", sev)
			}
		}
	}
}

func TestPersistenceOffersAutostartRemoval(t *testing.T) {
	acts := Suggest("persistence", "high", map[string]any{
		"Location":  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"EntryName": "Updater", "Target": `C:\Users\k\Downloads\svc.exe`,
		"TargetPath": `C:\Users\k\Downloads\svc.exe`, "Mechanism": "run-key",
	})
	if len(acts) == 0 || acts[0].Kind != RemoveAutostart {
		t.Fatalf("expected autostart removal first, got %+v", acts)
	}
	if !acts[0].Reversible {
		t.Error("removing an autostart entry is reversible and must say so")
	}
}

// A user consenting to something they do not understand has not consented.
func TestEveryActionExplainsItselfConcretely(t *testing.T) {
	acts := Suggest("c2", "critical", map[string]any{
		"ImagePath": `C:\x\bad.exe`, "ProcessName": "bad.exe", "PID": "9", "RemoteIP": "9.9.9.9",
	})
	for _, a := range acts {
		if a.Label == "" || a.Detail == "" {
			t.Errorf("%s is missing a label or detail", a.Kind)
		}
		if len(a.Detail) < 30 {
			t.Errorf("%s detail is too terse to be informed consent: %q", a.Kind, a.Detail)
		}
	}
}

func TestNoActionsWithoutUsableEvidence(t *testing.T) {
	if acts := Suggest("c2", "critical", map[string]any{}); len(acts) != 0 {
		t.Errorf("no evidence should yield no actions, got %+v", acts)
	}
	if acts := Suggest("unknown-area", "critical", map[string]any{"RemoteIP": "1.1.1.1"}); len(acts) != 0 {
		t.Errorf("unknown areas should yield no actions, got %+v", acts)
	}
	// A missing PID must not produce a kill action aimed at nothing.
	acts := Suggest("c2", "high", map[string]any{"RemoteIP": "1.1.1.1", "ProcessName": "x.exe"})
	for _, a := range acts {
		if a.Kind == KillProcess {
			t.Error("kill must not be offered without a process id")
		}
	}
}

func TestReversibilityIsReportedHonestly(t *testing.T) {
	acts := Suggest("c2", "critical", map[string]any{
		"ImagePath": `C:\x\bad.exe`, "ProcessName": "bad.exe", "PID": "9", "RemoteIP": "9.9.9.9",
	})
	for _, a := range acts {
		switch a.Kind {
		case KillProcess:
			if a.Reversible {
				t.Error("killing a process is not reversible and must not claim to be")
			}
		case BlockAddress, QuarantineFile:
			if !a.Reversible {
				t.Errorf("%s is reversible and should say so", a.Kind)
			}
		}
	}
}
