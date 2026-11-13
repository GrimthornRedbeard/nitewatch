// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package seal

import "errors"

// Persistent is Windows-only. Elsewhere the agent runs in replay mode for
// development and uses an Ephemeral key.
func Persistent() (*Key, string, error) {
	return nil, "", errors.New("a persistent sealing key is only kept on Windows")
}
