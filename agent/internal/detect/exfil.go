package detect

import (
	"strconv"
	"sync"
	"time"
)

// ExfilTracker remembers that a process read something sensitive, so a later
// upload by that same process can be explained.
//
// This is the answer to "what is inside that encrypted upload?" without
// decrypting anything. You do not need to read the bytes if you know what the
// program read off disk moments earlier:
//
//	stealer.exe read your saved passwords, then sent 180 KB to an address in RU
//
// That is a complete story built from two events we already have, and it is
// stronger evidence than payload inspection would be: it survives TLS 1.3,
// Encrypted Client Hello, DNS-over-HTTPS, custom encryption and compression.
// Nothing the malware does to the wire changes what it took off the disk.
type ExfilTracker struct {
	mu sync.Mutex
	// reads maps a PID to what sensitive material it recently touched.
	reads map[uint32]*sensitiveReads
	// window is how long a read stays relevant to a later upload. Stealers
	// collect and send within seconds; a long window would start attributing
	// unrelated traffic to an old read.
	window time.Duration
	// maxTracked bounds memory the same way the file tracker does.
	maxTracked int
}

type sensitiveReads struct {
	items   []sensitiveRead
	updated time.Time
}

type sensitiveRead struct {
	what string // human description: "your saved Chrome passwords"
	path string
	at   time.Time
}

// DefaultExfilWindow: collection and exfiltration are adjacent steps in every
// stealer. Two minutes is generous for the slowest of them and short enough
// that ordinary later traffic is not blamed on an old read.
const DefaultExfilWindow = 2 * time.Minute

// UploadThreshold is the volume that makes an upload worth explaining. Chosen
// above routine request traffic (headers, telemetry pings, API calls) and below
// the size of a useful credential haul — a Chrome Login Data file is tens of KB.
const UploadThreshold = 50 * 1024

func NewExfilTracker() *ExfilTracker {
	return &ExfilTracker{
		reads:      map[uint32]*sensitiveReads{},
		window:     DefaultExfilWindow,
		maxTracked: 256,
	}
}

// NoteSensitiveRead records that a process read a secret store.
func (t *ExfilTracker) NoteSensitiveRead(pid uint32, what, path string, at time.Time) {
	if what == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	st, ok := t.reads[pid]
	if !ok {
		if len(t.reads) >= t.maxTracked {
			t.evictOldestLocked()
		}
		st = &sensitiveReads{}
		t.reads[pid] = st
	}
	st.updated = at
	// One entry per distinct secret: a stealer reading the same file in a loop
	// should not look like it took ten different things.
	for _, r := range st.items {
		if r.path == path {
			return
		}
	}
	st.items = append(st.items, sensitiveRead{what: what, path: path, at: at})
}

// RecentReads returns the sensitive material a process touched within the
// window, most recent first.
func (t *ExfilTracker) RecentReads(pid uint32, now time.Time) []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	st, ok := t.reads[pid]
	if !ok {
		return nil
	}
	var out []string
	for i := len(st.items) - 1; i >= 0; i-- {
		if now.Sub(st.items[i].at) <= t.window {
			out = append(out, st.items[i].what)
		}
	}
	return out
}

// Forget drops a process's history when it exits.
func (t *ExfilTracker) Forget(pid uint32) {
	t.mu.Lock()
	delete(t.reads, pid)
	t.mu.Unlock()
}

func (t *ExfilTracker) evictOldestLocked() {
	var oldestPID uint32
	var oldest time.Time
	for pid, st := range t.reads {
		if oldest.IsZero() || st.updated.Before(oldest) {
			oldest, oldestPID = st.updated, pid
		}
	}
	delete(t.reads, oldestPID)
}

// detectExfilAfterRead fires when a process uploads a meaningful amount shortly
// after reading a secret store.
func detectExfilAfterRead(s Subject, e *Engine) map[string]any {
	if e.exfil == nil || s.Conn.Inbound {
		return nil
	}
	if s.Conn.BytesSent < UploadThreshold {
		return nil
	}
	taken := e.exfil.RecentReads(s.Conn.PID, s.Conn.LastSeen)
	if len(taken) == 0 {
		return nil
	}
	return map[string]any{
		"WhatWasTaken": joinList(taken),
		"UploadSize":   humanBytes(s.Conn.BytesSent),
	}
}

func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	out := ""
	for i, s := range items[:len(items)-1] {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out + ", and " + items[len(items)-1]
}

// humanBytes renders a size the way a person reads one.
func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmtFloat(float64(n)/(1<<30)) + " GB"
	case n >= 1<<20:
		return fmtFloat(float64(n)/(1<<20)) + " MB"
	case n >= 1<<10:
		return fmtFloat(float64(n)/(1<<10)) + " KB"
	}
	return fmtInt(n) + " bytes"
}

func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }
func fmtInt(n uint64) string    { return strconv.FormatUint(n, 10) }
