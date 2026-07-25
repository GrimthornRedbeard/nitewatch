// Package event defines NiteWatch's source-agnostic telemetry vocabulary.
// Every EventSource (real ETW on Windows, the JSONL replay source in tests)
// emits NormalizedEvent values so the rest of the agent never sees ETW schemas.
package event

import (
	"fmt"
	"time"
)

// Kind enumerates the telemetry record types the flight recorder understands.
type Kind string

const (
	KindProcStart  Kind = "ProcStart"
	KindProcExit   Kind = "ProcExit"
	KindNetConnect Kind = "NetConnect"
	KindDNSQuery   Kind = "DNSQuery"
	KindFileWrite  Kind = "FileWrite"
)

// NormalizedEvent is the source-agnostic representation of one telemetry record.
// JSON tags are load-bearing: the replay source and testdata fixtures serialize
// to exactly these names.
type NormalizedEvent struct {
	Seq   uint64    `json:"seq"`   // monotonic within a run; assigned by the source
	Kind  Kind      `json:"kind"`
	Time  time.Time `json:"time"`
	PID   uint32    `json:"pid"`
	PPID  uint32    `json:"ppid,omitempty"`  // ProcStart only
	Image string    `json:"image,omitempty"` // full path to the acting process image

	// Network (NetConnect):
	RemoteIP   string `json:"remoteIP,omitempty"`
	RemotePort uint16 `json:"remotePort,omitempty"`
	Proto      string `json:"proto,omitempty"` // "TCP"/"UDP"

	// DNS (DNSQuery):
	QueryName string   `json:"queryName,omitempty"`
	Answers   []string `json:"answers,omitempty"`

	// File (FileWrite):
	Path string `json:"path,omitempty"`

	// Opportunistic enrichment (signer, hash, ...).
	Extra map[string]string `json:"extra,omitempty"`
}

func (e NormalizedEvent) String() string {
	return fmt.Sprintf("#%d %s pid=%d %s", e.Seq, e.Kind, e.PID, e.Image)
}
