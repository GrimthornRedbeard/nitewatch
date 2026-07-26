// Package autostart watches the places software registers itself to run at
// startup, and reports what appears there.
//
// Approach: periodic snapshot and diff, rather than intercepting registry
// writes. Registry ETW gives you the writing process — valuable — but its
// events carry key handles rather than paths, so reconstructing which key was
// touched means tracking every handle open and close and getting it right.
// Snapshotting is boring, reliable, and catches an autostart entry however it
// was created, including by mechanisms we never thought to hook. Attribution to
// the writing process is layered on top where the causal graph supplies it.
package autostart

import (
	"sort"
	"strings"
)

// Kind is the autostart mechanism an entry uses.
type Kind string

const (
	KindRunKey        Kind = "run-key"
	KindRunOnce       Kind = "run-once"
	KindService       Kind = "service"
	KindStartupFolder Kind = "startup-folder"
	KindWinlogon      Kind = "winlogon"
	KindIFEO          Kind = "image-hijack"
	KindAppInit       Kind = "appinit-dll"
	KindScheduledTask Kind = "scheduled-task"
)

// Describe renders a mechanism in words a non-technical user can act on.
func (k Kind) Describe() string {
	switch k {
	case KindRunKey, KindRunOnce:
		return "run automatically when you sign in"
	case KindService:
		return "run in the background as a system service"
	case KindStartupFolder:
		return "run automatically when you sign in (Startup folder)"
	case KindWinlogon:
		return "run as part of the Windows sign-in process"
	case KindIFEO:
		return "launch itself whenever another program is started"
	case KindAppInit:
		return "load itself into other programs"
	case KindScheduledTask:
		return "run on a schedule"
	}
	return "start automatically"
}

// Suspicious marks mechanisms that legitimate consumer software essentially
// never uses. A Run key is ordinary; hijacking another program's launch is not.
func (k Kind) Suspicious() bool {
	return k == KindIFEO || k == KindAppInit || k == KindWinlogon
}

// Entry is one autostart registration.
type Entry struct {
	Kind     Kind   `json:"kind"`
	Location string `json:"location"` // where it lives (registry key or folder)
	Name     string `json:"name"`     // the value/file name
	Target   string `json:"target"`   // what will be executed
}

// ID uniquely identifies an entry by its slot, independent of target, so that
// REPLACING an existing entry's target is detected as a change rather than as
// an unrelated add and remove.
func (e Entry) ID() string {
	return strings.ToLower(string(e.Kind) + "|" + e.Location + "|" + e.Name)
}

// Snapshot is the full set of autostart entries at a point in time.
type Snapshot struct {
	Entries []Entry `json:"entries"`
}

// Change describes how the autostart configuration differs from before.
type Change struct {
	Entry Entry
	// Previous is set when an existing slot's target was replaced — a program
	// quietly swapping what an existing autostart runs is a hijack, and looks
	// nothing like a fresh install.
	Previous string
}

// Diff reports entries that are new or whose target changed.
//
// Removals are deliberately not reported: uninstalling software is normal and
// alerting on it would be pure noise.
func Diff(before, after Snapshot) []Change {
	prev := make(map[string]Entry, len(before.Entries))
	for _, e := range before.Entries {
		prev[e.ID()] = e
	}

	var out []Change
	for _, e := range after.Entries {
		old, existed := prev[e.ID()]
		switch {
		case !existed:
			out = append(out, Change{Entry: e})
		case !sameTarget(old.Target, e.Target):
			out = append(out, Change{Entry: e, Previous: old.Target})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Entry.ID() < out[j].Entry.ID() })
	return out
}

// sameTarget compares command lines tolerantly: Windows quotes and cases paths
// inconsistently, and a spurious "your autostart changed" alert is worse than
// missing a whitespace-only edit.
func sameTarget(a, b string) bool {
	return normalizeTarget(a) == normalizeTarget(b)
}

func normalizeTarget(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, `"`, "")
	return strings.Join(strings.Fields(s), " ")
}

// TargetPath extracts the executable path from a command line, so a target can
// be matched against a known process image.
func TargetPath(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if t[0] == '"' {
		if i := strings.Index(t[1:], `"`); i >= 0 {
			return t[1 : 1+i]
		}
		return strings.Trim(t, `"`)
	}
	// Unquoted: take up to the first argument separator. Paths with spaces and
	// no quotes are ambiguous by construction; prefer the .exe boundary.
	lower := strings.ToLower(t)
	if i := strings.Index(lower, ".exe"); i >= 0 {
		return t[:i+4]
	}
	if i := strings.IndexAny(t, " \t"); i >= 0 {
		return t[:i]
	}
	return t
}
