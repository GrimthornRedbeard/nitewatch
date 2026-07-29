// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package source

import "errors"

// NewETWSource is unavailable off Windows; the replay source drives dev/test on
// other platforms.
func NewETWSource() (EventSource, error) {
	return nil, errors.New("ETW source is only available on Windows; use --replay on this platform")
}
