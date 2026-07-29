// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package source

import (
	"bufio"
	"context"
	"encoding/json"
	"os"

	"github.com/threattape/nitewatch/agent/internal/event"
)

// replaySource streams NormalizedEvents from a .jsonl file (one event per line).
// It is the cross-platform test driver and the "record ETW once, replay forever"
// fixture format.
type replaySource struct {
	path string
	f    *os.File
}

// NewReplaySource returns an EventSource backed by the JSONL file at path.
func NewReplaySource(path string) (EventSource, error) {
	return &replaySource{path: path}, nil
}

func (r *replaySource) Events(ctx context.Context) (<-chan event.NormalizedEvent, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return nil, err
	}
	r.f = f

	out := make(chan event.NormalizedEvent)
	go func() {
		defer close(out)
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var e event.NormalizedEvent
			if err := json.Unmarshal(line, &e); err != nil {
				continue // a corrupt line shouldn't crash the recorder
			}
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (r *replaySource) Close() error {
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}
