// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package autostart

// Scan is unavailable off Windows; autostart mechanisms are Windows-specific.
// The diff logic above is platform-independent and fully tested, so only this
// collection step is gated.
func Scan() (Snapshot, error) { return Snapshot{}, nil }
