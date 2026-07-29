// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package autostart

import "testing"

func snap(entries ...Entry) Snapshot { return Snapshot{Entries: entries} }

func TestDiffReportsNewEntries(t *testing.T) {
	before := snap(Entry{KindRunKey, `HKCU\...\Run`, "OneDrive", `C:\OneDrive.exe`})
	after := snap(
		Entry{KindRunKey, `HKCU\...\Run`, "OneDrive", `C:\OneDrive.exe`},
		Entry{KindRunKey, `HKCU\...\Run`, "Updater", `C:\Users\k\AppData\svc.exe`},
	)
	got := Diff(before, after)
	if len(got) != 1 || got[0].Entry.Name != "Updater" {
		t.Fatalf("want the new entry only, got %+v", got)
	}
	if got[0].Previous != "" {
		t.Error("a brand-new entry has no previous target")
	}
}

// A program quietly swapping what an existing autostart runs is a hijack, and
// looks nothing like a fresh install — it must not be missed.
func TestDiffDetectsTargetReplacement(t *testing.T) {
	before := snap(Entry{KindRunKey, `HKCU\...\Run`, "OneDrive", `C:\Program Files\OneDrive.exe`})
	after := snap(Entry{KindRunKey, `HKCU\...\Run`, "OneDrive", `C:\Users\k\AppData\evil.exe`})

	got := Diff(before, after)
	if len(got) != 1 {
		t.Fatalf("a replaced target must be reported: %+v", got)
	}
	if got[0].Previous != `C:\Program Files\OneDrive.exe` {
		t.Errorf("the previous target should be carried for the narrative, got %q", got[0].Previous)
	}
}

// Uninstalling software is normal; alerting on it would be pure noise.
func TestDiffIgnoresRemovals(t *testing.T) {
	before := snap(
		Entry{KindRunKey, `HKCU\...\Run`, "A", `C:\a.exe`},
		Entry{KindRunKey, `HKCU\...\Run`, "B", `C:\b.exe`},
	)
	after := snap(Entry{KindRunKey, `HKCU\...\Run`, "A", `C:\a.exe`})
	if got := Diff(before, after); len(got) != 0 {
		t.Fatalf("removals must not be reported, got %+v", got)
	}
}

// Windows is inconsistent about quoting and case; a spurious "your autostart
// changed" alert is worse than missing a whitespace-only edit.
func TestDiffToleratesQuotingAndCase(t *testing.T) {
	before := snap(Entry{KindRunKey, `HKCU\...\Run`, "App", `"C:\Program Files\App\app.exe" --start`})
	after := snap(Entry{KindRunKey, `HKCU\...\Run`, "App", `C:\Program Files\App\app.exe  --start`})
	if got := Diff(before, after); len(got) != 0 {
		t.Fatalf("cosmetic differences must not alert, got %+v", got)
	}
}

func TestDiffTreatsSameNameInDifferentLocationsSeparately(t *testing.T) {
	before := snap(Entry{KindRunKey, `HKCU\...\Run`, "Updater", `C:\a.exe`})
	after := snap(
		Entry{KindRunKey, `HKCU\...\Run`, "Updater", `C:\a.exe`},
		Entry{KindRunKey, `HKLM\...\Run`, "Updater", `C:\a.exe`}, // machine-wide is a different slot
	)
	got := Diff(before, after)
	if len(got) != 1 || got[0].Entry.Location != `HKLM\...\Run` {
		t.Fatalf("a same-named entry elsewhere is a new registration: %+v", got)
	}
}

func TestFirstSnapshotReportsEverything(t *testing.T) {
	after := snap(
		Entry{KindRunKey, `HKCU\...\Run`, "A", `C:\a.exe`},
		Entry{KindService, `HKLM\...\Services\X`, "X", `C:\x.exe`},
	)
	if got := Diff(Snapshot{}, after); len(got) != 2 {
		t.Fatalf("an empty baseline yields every entry as new, got %d", len(got))
	}
}

func TestTargetPathExtraction(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" --flag`: `C:\Program Files\App\app.exe`,
		`C:\Windows\system32\svchost.exe -k n`:  `C:\Windows\system32\svchost.exe`,
		`C:\tools\thing.exe`:                    `C:\tools\thing.exe`,
		`rundll32 shell32.dll,Control_RunDLL`:   `rundll32`,
		``:                                      ``,
	}
	for in, want := range cases {
		if got := TargetPath(in); got != want {
			t.Errorf("TargetPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSuspiciousMechanisms(t *testing.T) {
	// Legitimate consumer software essentially never uses these.
	for _, k := range []Kind{KindIFEO, KindAppInit, KindWinlogon} {
		if !k.Suspicious() {
			t.Errorf("%s should be flagged as an unusual mechanism", k)
		}
	}
	// These are how ordinary software starts itself.
	for _, k := range []Kind{KindRunKey, KindService, KindStartupFolder} {
		if k.Suspicious() {
			t.Errorf("%s is an ordinary mechanism and must not be flagged as unusual", k)
		}
	}
	// Every mechanism must have user-facing wording.
	for _, k := range []Kind{KindRunKey, KindRunOnce, KindService, KindStartupFolder,
		KindWinlogon, KindIFEO, KindAppInit, KindScheduledTask} {
		if k.Describe() == "" {
			t.Errorf("%s has no plain-English description", k)
		}
	}
}
