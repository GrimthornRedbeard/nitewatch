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

// Undo records are read back from the database and acted on with elevated
// privileges. If that file is writable by an attacker — and it sits beside the
// agent, potentially in a user-writable folder — unvalidated records are an
// arbitrary file-move and registry-write primitive running as SYSTEM.
func TestValidateUndoRejectsTamperedRecords(t *testing.T) {
	const qdir = `C:\Agent\quarantine`

	bad := []struct {
		name string
		kind Kind
		undo map[string]string
	}{
		{"restore from outside quarantine", QuarantineFile,
			map[string]string{"from": `C:\Users\k\evil.dll`, "to": `C:\Windows\System32\important.dll`}},
		{"traversal out of quarantine", QuarantineFile,
			map[string]string{"from": qdir + `\..\..\Windows\System32\x.dll`, "to": `C:\Windows\System32\x.dll`}},
		{"registry write outside autostart", RemoveAutostart,
			map[string]string{"kind": "registry", "location": `HKLM\SYSTEM\CurrentControlSet\Services\Evil`, "name": "ImagePath", "value": "evil.exe"}},
		{"startup file from outside quarantine", RemoveAutostart,
			map[string]string{"kind": "file", "from": `C:\Users\k\evil.lnk`, "to": `C:\Startup\evil.lnk`}},
		{"firewall rule we never created", BlockAddress,
			map[string]string{"rule": "Core Networking - DNS (UDP-Out)", "ip": "1.2.3.4"}},
		{"firewall undo with junk address", BlockAddress,
			map[string]string{"rule": "NiteWatch block x", "ip": "not-an-ip"}},
	}
	for _, c := range bad {
		if err := ValidateUndo(c.kind, c.undo, qdir); err == nil {
			t.Errorf("%s: tampered undo record was accepted", c.name)
		}
	}

	good := []struct {
		name string
		kind Kind
		undo map[string]string
	}{
		{"our own quarantine restore", QuarantineFile,
			map[string]string{"from": qdir + `\20260726-x.exe.quarantined`, "to": `C:\Users\k\Downloads\x.exe`}},
		{"our own run-key restore", RemoveAutostart,
			map[string]string{"kind": "registry", "location": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "name": "App", "value": `C:\App\a.exe`}},
		{"our own firewall rule", BlockAddress,
			map[string]string{"rule": "NiteWatch block 185.4.3.2", "ip": "185.4.3.2"}},
	}
	for _, c := range good {
		if err := ValidateUndo(c.kind, c.undo, qdir); err != nil {
			t.Errorf("%s: legitimate undo rejected: %v", c.name, err)
		}
	}
}

// Kill cannot be undone and must not pretend otherwise.
func TestValidateUndoRejectsUnUndoableKinds(t *testing.T) {
	if err := ValidateUndo(KillProcess, map[string]string{"pid": "1"}, `C:\q`); err == nil {
		t.Fatal("killing a process is not reversible and must be refused")
	}
}

// A playbook that says "the button below" must be accompanied by a button.
//
// This is the regression this test exists for: Suggest handled only "c2" and
// "persistence", so all three ransomware rules and the credential-theft rule
// rendered with an empty action row while their own text told the reader to
// press something. The critical ransomware alert — the one where seconds
// matter — was the worst case. Pointing someone at a control that is not there
// is the exact "confident wrongness" this product is built to avoid.
//
// The areas and severities below mirror agent/rules/*.yaml. If a new pack adds
// a "button below" playbook step for a new area, add it here too.
func TestEveryAreaPromisingAButtonProvidesOne(t *testing.T) {
	// Evidence as the ledger actually returns it: numbers have round-tripped
	// through JSON, so PID arrives as float64, not uint32.
	evidence := func(extra map[string]any) map[string]any {
		ev := map[string]any{
			"ImagePath":   `C:\Users\kevin\Downloads\invoice.exe`,
			"ProcessName": "invoice.exe",
			"PID":         float64(300),
		}
		for k, v := range extra {
			ev[k] = v
		}
		return ev
	}

	cases := []struct {
		area     string
		severity string
		ev       map[string]any
		wantKind Kind // the action the playbook text specifically promises
	}{
		{"ransomware", "critical", evidence(nil), KillProcess},
		{"ransomware", "high", evidence(nil), KillProcess},
		{"credentials", "critical", evidence(map[string]any{
			"SecretPath": `C:\Users\kevin\AppData\Local\BrowserCo\Login Data`,
		}), KillProcess},
		{"c2", "critical", evidence(map[string]any{"RemoteIP": "185.4.3.2"}), KillProcess},
		{"persistence", "high", evidence(map[string]any{
			"Location": `HKCU\...\Run`, "EntryName": "Updater",
		}), RemoveAutostart},
	}

	for _, c := range cases {
		acts := Suggest(c.area, c.severity, c.ev)
		if len(acts) == 0 {
			t.Errorf("%s/%s: no actions offered, but the playbook tells the user to press a button",
				c.area, c.severity)
			continue
		}
		var found bool
		for _, a := range acts {
			if a.Kind == c.wantKind {
				found = true
			}
			if a.Label == "" || a.Detail == "" {
				t.Errorf("%s/%s: action %v has empty label or detail", c.area, c.severity, a.Kind)
			}
		}
		if !found {
			t.Errorf("%s/%s: offered %v, want one of kind %v", c.area, c.severity, kinds(acts), c.wantKind)
		}
	}
}

// Stopping the thing must be offered before destroying it — the ordering is
// the safety property, not a cosmetic one.
func TestRansomwareOffersStopBeforeQuarantine(t *testing.T) {
	acts := Suggest("ransomware", "critical", map[string]any{
		"ImagePath": `C:\x\bad.exe`, "ProcessName": "bad.exe", "PID": float64(42),
	})
	var killAt, quarAt = -1, -1
	for i, a := range acts {
		switch a.Kind {
		case KillProcess:
			killAt = i
		case QuarantineFile:
			quarAt = i
		}
	}
	if killAt < 0 || quarAt < 0 {
		t.Fatalf("want both stop and quarantine, got %v", kinds(acts))
	}
	if killAt > quarAt {
		t.Errorf("quarantine offered before stopping the process: %v", kinds(acts))
	}
}

// The PID must survive the JSON round-trip as an integer. Formatted with %v a
// float64 PID above ~1e6 becomes "1.234568e+06", which taskkill rejects —
// silently breaking the one button that stops active ransomware on a machine
// with long uptime.
func TestLargePIDIsNotFormattedAsExponent(t *testing.T) {
	acts := Suggest("ransomware", "critical", map[string]any{
		"ImagePath": `C:\x\bad.exe`, "ProcessName": "bad.exe", "PID": float64(1234568),
	})
	for _, a := range acts {
		if a.Kind == KillProcess {
			if got := a.Params["pid"]; got != "1234568" {
				t.Errorf("pid = %q, want \"1234568\"", got)
			}
			return
		}
	}
	t.Fatal("no stop action offered")
}

func kinds(as []Action) []Kind {
	out := make([]Kind, 0, len(as))
	for _, a := range as {
		out = append(out, a.Kind)
	}
	return out
}

// Reported from a live machine: an alert for a connection whose program could
// not be identified offered "Stop An unknown program now (cannot be undone)".
// A button to irreversibly stop something we cannot name is not an action
// anybody can take responsibly.
func TestNoProgramActionsWhenTheProgramIsUnknown(t *testing.T) {
	acts := Suggest("c2", "critical", map[string]any{
		"ImagePath":   "",
		"ProcessName": "an unidentified program",
		"PID":         float64(1234),
		"RemoteIP":    "2620:100:601f:17::a27d:911",
	})
	for _, a := range acts {
		switch a.Kind {
		case KillProcess, QuarantineFile:
			t.Errorf("offered %v for a program we cannot identify: %q", a.Kind, a.Label)
		}
	}
	// Blocking the destination is still meaningful: it acts on the address,
	// not on the program.
	var canBlock bool
	for _, a := range acts {
		if a.Kind == BlockAddress {
			canBlock = true
		}
	}
	if !canBlock {
		t.Error("blocking the address should still be offered")
	}
}

// The System alert offered "Stop System now (cannot be undone)" and "Quarantine
// this program". Terminating PID 4 stops the computer, and "System" is not a
// file that can be moved anywhere.
func TestNoActionsAgainstTheKernel(t *testing.T) {
	acts := Suggest("credentials", "critical", map[string]any{
		"ImagePath": "System", "ProcessName": "System", "PID": float64(4),
	})
	for _, a := range acts {
		switch a.Kind {
		case KillProcess, QuarantineFile:
			t.Errorf("offered %v against the Windows kernel: %q", a.Kind, a.Label)
		}
	}
}
