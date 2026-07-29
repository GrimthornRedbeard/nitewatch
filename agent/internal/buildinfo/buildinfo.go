// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package buildinfo reports which build of NiteWatch is running.
//
// This exists because the product is about to be downloadable by strangers,
// and the first question about any bug report is "which build?". Until now the
// answer lived in a single startup log line that nobody reading the dashboard
// would ever see.
//
// The commit is not stamped in by the build script. Go records it already —
// runtime/debug carries the VCS revision, its timestamp, and whether the tree
// had uncommitted changes — so reading it back cannot drift from the source it
// was built from, which a hand-passed ldflags value can and eventually does.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

func runtimeVersion() string { return runtime.Version() }

// Info describes the running build.
type Info struct {
	Version string `json:"version"`
	// Commit is the full VCS revision, empty when built outside a repository.
	Commit string `json:"commit,omitempty"`
	// Short is the abbreviated commit, for display.
	Short string `json:"short,omitempty"`
	// Modified reports that the tree had uncommitted changes at build time.
	// Shown rather than hidden: a build that does not correspond to any commit
	// is exactly the build whose bug reports are hardest to act on.
	Modified bool      `json:"modified,omitempty"`
	Built    time.Time `json:"built,omitempty"`
	Go       string    `json:"go,omitempty"`
}

// Label is the one-line human form: "0.1.0 (23e92ed)", with "+dirty" appended
// when the tree was not clean.
func (i Info) Label() string {
	s := i.Version
	if i.Short != "" {
		s += " (" + i.Short + ")"
	}
	if i.Modified {
		s += "+dirty"
	}
	return s
}

// Read returns the running build's identity. version comes from the caller so
// the release number stays where a human sets it; everything else is recovered
// from what the toolchain already recorded.
func Read(version string) Info {
	out := Info{Version: version, Go: strings.TrimPrefix(runtimeVersion(), "go")}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			out.Commit = s.Value
			if len(s.Value) >= 7 {
				out.Short = s.Value[:7]
			}
		case "vcs.modified":
			out.Modified = s.Value == "true"
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				out.Built = t
			}
		}
	}
	return out
}
