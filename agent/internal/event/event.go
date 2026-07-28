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
	// KindFileRead is a file being OPENED OR READ, not modified. Kept distinct
	// from FileWrite because the two answer different questions: reads reveal
	// credential theft, writes reveal encryption. Conflating them made a file
	// picker rendering thumbnails look like ransomware.
	KindFileRead Kind = "FileRead"
	// KindRegPersist is an autostart installation: a Run key, service, scheduled
	// task, startup-folder drop, or WMI event subscription. Legitimate software
	// does this at install time; implants do it to survive reboot.
	KindRegPersist Kind = "RegPersist"
)

// NormalizedEvent is the source-agnostic representation of one telemetry record.
// JSON tags are load-bearing: the replay source and testdata fixtures serialize
// to exactly these names.
type NormalizedEvent struct {
	Seq  uint64    `json:"seq"` // monotonic within a run; assigned by the source
	Kind Kind      `json:"kind"`
	Time time.Time `json:"time"`
	PID  uint32    `json:"pid"`
	PPID uint32    `json:"ppid,omitempty"` // ProcStart only
	// StartKey is Windows' ProcessStartKey: monotonically increasing and never
	// reused, unlike a PID. Present on ProcStart from Windows 10 1809 onward,
	// zero otherwise. It is what makes "is this the same process?" an exact
	// question rather than a guess.
	StartKey uint64 `json:"startKey,omitempty"`
	Image    string `json:"image,omitempty"` // full path to the acting process image

	// Network (NetConnect). The kernel reports source/destination relative to
	// the packet, so on inbound traffic the "destination" is the LOCAL host.
	// Sources fill both ends as reported; the collector decides which is the
	// remote peer (whichever is not one of this machine's own addresses).
	SrcIP      string `json:"srcIP,omitempty"`
	SrcPort    uint16 `json:"srcPort,omitempty"`
	RemoteIP   string `json:"remoteIP,omitempty"`
	RemotePort uint16 `json:"remotePort,omitempty"`
	Proto      string `json:"proto,omitempty"` // "TCP"/"UDP"
	// BytesSent/BytesRecv are per-event transfer sizes. Volume is the one thing
	// about an encrypted conversation that is always visible, and it is what
	// separates a heartbeat from an upload of your documents.
	BytesSent uint64 `json:"bytesSent,omitempty"`
	BytesRecv uint64 `json:"bytesRecv,omitempty"`
	Inbound   bool   `json:"inbound,omitempty"`

	// DNS (DNSQuery):
	QueryName string   `json:"queryName,omitempty"`
	Answers   []string `json:"answers,omitempty"`

	// File (FileWrite):
	Path string `json:"path,omitempty"`

	// Persistence (RegPersist): what autostart mechanism was installed, where,
	// and what it will run.
	PersistKind     string `json:"persistKind,omitempty"` // run-key|service|scheduled-task|startup-folder|wmi
	PersistLocation string `json:"persistLocation,omitempty"`
	PersistTarget   string `json:"persistTarget,omitempty"`

	// Code signing (ProcStart). Signed defaults to false: absent signature data
	// must never read as "signed", or suppression rules would trust unknowns.
	Signed bool   `json:"signed,omitempty"`
	Signer string `json:"signer,omitempty"`

	// Opportunistic enrichment (signer, hash, ...).
	Extra map[string]string `json:"extra,omitempty"`
}

func (e NormalizedEvent) String() string {
	return fmt.Sprintf("#%d %s pid=%d %s", e.Seq, e.Kind, e.PID, e.Image)
}
