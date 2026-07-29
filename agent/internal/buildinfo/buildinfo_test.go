// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package buildinfo

import "testing"

// The label is what a bug report will quote, so it has to be unambiguous about
// a build that does not correspond to a commit.
func TestLabel(t *testing.T) {
	cases := []struct {
		in   Info
		want string
	}{
		{Info{Version: "0.1.0"}, "0.1.0"},
		{Info{Version: "0.1.0", Short: "23e92ed"}, "0.1.0 (23e92ed)"},
		{Info{Version: "0.1.0", Short: "23e92ed", Modified: true}, "0.1.0 (23e92ed)+dirty"},
	}
	for _, c := range cases {
		if got := c.in.Label(); got != c.want {
			t.Errorf("Label() = %q, want %q", got, c.want)
		}
	}
}

// Built by `go test`, so the toolchain records a revision for this very tree.
func TestReadRecoversTheCommit(t *testing.T) {
	i := Read("0.1.0")
	if i.Version != "0.1.0" {
		t.Errorf("version = %q", i.Version)
	}
	if i.Go == "" {
		t.Error("no Go version recovered")
	}
	if i.Commit != "" && i.Short == "" {
		t.Error("commit present but short form empty")
	}
}
