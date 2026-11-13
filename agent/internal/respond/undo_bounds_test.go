// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package respond

import "testing"

// R-02. Even a record the agent wrote itself is checked against the action it
// belongs to, so an undo can only put back what that action took away, and
// never writes into the Windows directory or an arbitrary high-risk value.
func TestValidateUndoBoundsTheReversal(t *testing.T) {
	const qdir = `C:\Agent\quarantine`
	winlogon := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	ifeo := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe`
	startup := `C:\Users\k\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

	bad := []struct {
		name   string
		kind   Kind
		undo   map[string]string
		params map[string]string
	}{
		{"restore into System32", QuarantineFile,
			map[string]string{"from": qdir + `\1-x.dll.quarantined`, "to": `C:\Windows\System32\x.dll`},
			map[string]string{"path": `C:\Windows\System32\x.dll`}},
		{"restore somewhere other than where it came from", QuarantineFile,
			map[string]string{"from": qdir + `\1-x.exe.quarantined`, "to": `C:\Program Files\Vendor\x.exe`},
			map[string]string{"path": `C:\Users\k\Downloads\x.exe`}},
		{"restore without the content hash recorded at quarantine", QuarantineFile,
			map[string]string{"from": qdir + `\1-x.exe.quarantined`, "to": `C:\Users\k\Downloads\x.exe`},
			map[string]string{"path": `C:\Users\k\Downloads\x.exe`}},
		{"restore through a trailing-dot alias of the Windows folder", QuarantineFile,
			map[string]string{"from": qdir + `\1-x.dll.quarantined`, "to": `C:\Windows.\System32\x.dll`, "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
			map[string]string{"path": `C:\Windows.\System32\x.dll`}},
		{"restore to a device path", QuarantineFile,
			map[string]string{"from": qdir + `\1-x.exe.quarantined`, "to": `\\?\C:\Windows\x.exe`},
			map[string]string{"path": `\\?\C:\Windows\x.exe`}},
		{"startup file restored outside the startup folder", RemoveAutostart,
			map[string]string{"kind": "file", "from": qdir + `\startup-a.lnk`, "to": `C:\Windows\System32\a.dll`},
			map[string]string{"location": startup, "name": "a.lnk"}},
		{"startup file restored to a different name", RemoveAutostart,
			map[string]string{"kind": "file", "from": qdir + `\startup-a.lnk`, "to": startup + `\b.lnk`},
			map[string]string{"location": startup, "name": "a.lnk"}},
		{"winlogon value that is not what was removed", RemoveAutostart,
			map[string]string{"kind": "registry", "location": winlogon, "name": "Userinit", "value": `C:\Users\k\evil.exe`},
			map[string]string{"location": winlogon, "name": "Userinit", "target": `C:\Windows\system32\userinit.exe,`}},
		{"IFEO debugger that is not what was removed", RemoveAutostart,
			map[string]string{"kind": "registry", "location": ifeo, "name": "Debugger", "value": `C:\Users\k\evil.exe`},
			map[string]string{"location": ifeo, "name": "Debugger", "target": `C:\Tools\dbg.exe`}},
		{"registry value under a different name", RemoveAutostart,
			map[string]string{"kind": "registry", "location": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "name": "Other", "value": `C:\a.exe`},
			map[string]string{"location": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "name": "App"}},
	}
	for _, c := range bad {
		if err := ValidateUndo(c.kind, c.undo, c.params, qdir); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}

	good := []struct {
		name   string
		kind   Kind
		undo   map[string]string
		params map[string]string
	}{
		{"quarantine restored to its own path", QuarantineFile,
			map[string]string{"from": qdir + `\1-x.exe.quarantined`, "to": `C:\Users\k\Downloads\x.exe`, "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
			map[string]string{"path": `c:/users/k/downloads/x.exe`}},
		{"startup file restored to its own path", RemoveAutostart,
			map[string]string{"kind": "file", "from": qdir + `\startup-a.lnk`, "to": startup + `\a.lnk`, "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
			map[string]string{"location": startup, "name": "a.lnk"}},
		{"run key restored", RemoveAutostart,
			map[string]string{"kind": "registry", "location": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "name": "App", "value": `"C:\App\a.exe" --tray`},
			map[string]string{"location": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "name": "App"}},
		{"winlogon restored to exactly what was removed", RemoveAutostart,
			map[string]string{"kind": "registry", "location": winlogon, "name": "Userinit", "value": `C:\Windows\system32\userinit.exe,`},
			map[string]string{"location": winlogon, "name": "Userinit", "target": `C:\Windows\system32\userinit.exe,`}},
	}
	for _, c := range good {
		if err := ValidateUndo(c.kind, c.undo, c.params, qdir); err != nil {
			t.Errorf("%s: rejected: %v", c.name, err)
		}
	}
}

// Quarantining a file inside the Windows directory is never offered: it can
// leave the machine unbootable, and an undo into that folder is refused, so
// the action would be one-way.
func TestQuarantineNotOfferedInsideWindows(t *testing.T) {
	for _, p := range []string{`C:\Windows\System32\evil.exe`, `c:/windows/syswow64/x.exe`} {
		for _, a := range Suggest("c2", "critical", map[string]any{
			"ImagePath": p, "ProcessName": "x.exe", "PID": "9", "RemoteIP": "9.9.9.9",
		}) {
			if a.Kind == QuarantineFile {
				t.Errorf("quarantine offered for %s", p)
			}
		}
	}
}
