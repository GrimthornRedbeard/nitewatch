// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package source acquires telemetry and emits event.NormalizedEvent values.
// The EventSource interface is the single seam between telemetry acquisition
// and analysis: the real ETW consumer (Windows) and the JSONL replay source
// (any OS, tests) both satisfy it.
package source

import (
	"context"

	"github.com/threattape/nitewatch/agent/internal/event"
)

// EventSource streams normalized telemetry until its context is cancelled or
// the underlying source is exhausted, at which point it closes the channel.
type EventSource interface {
	Events(ctx context.Context) (<-chan event.NormalizedEvent, error)
	Close() error
}
