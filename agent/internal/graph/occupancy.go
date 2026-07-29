// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"strings"
	"time"

	gr "github.com/ShaneDolphin/gorapide"
)

// occupant is one process's tenure of a PID.
//
// A PID identifies a process only among the processes alive right now. Windows
// recycles them, and Chromium-based applications churn through short-lived
// children faster than anything else on a desktop, so on a real machine the
// same number belongs to a succession of unrelated programs over the course of
// a minute.
//
// Recording the tenure — who held it, and between which two instants — is what
// lets an event be attributed to the process that was actually running when it
// happened, rather than to whoever holds the number by the time we get around
// to asking.
type occupant struct {
	// key is the Windows ProcessStartKey: monotonically increasing, never
	// reused, and therefore an actual identity rather than a slot number. Zero
	// when unknown — the process predates the agent, or the field was absent.
	key   uint64
	image string
	node  gr.EventID
	start time.Time
	end   time.Time
	// closed is an explicit flag rather than a zero-valued end, because a zero
	// timestamp is a legitimate value: replay traces and tests carry events
	// with no time at all, and treating those as "still running" made an exit
	// event silently fail to close anything.
	closed bool
}

func (o occupant) live() bool { return !o.closed }

// covers reports whether this occupant held the PID at the given instant.
//
// The start bound is inclusive and the end bound exclusive, so the instant a
// process exits belongs to its successor rather than to both.
func (o occupant) covers(at time.Time) bool {
	if at.Before(o.start) {
		return false
	}
	return o.live() || at.Before(o.end)
}

// procTable maps a PID to its succession of occupants, oldest first.
//
// Growth is bounded by the window rotation rather than by pruning here: each
// poset generation gets a fresh table, and only processes still live are
// carried across. A tenure requires a ProcStart event, so a table can never
// hold more tenures than its generation holds events.
type procTable map[uint32][]occupant

// begin records a process taking over a PID.
//
// Any occupant still marked live is closed at this instant. That is the point
// of the whole design: a start event is proof the previous tenure ended, so a
// missed exit — which is the common case, since exits are easy to drop under
// load — repairs itself rather than leaving a stale mapping that swallows
// somebody else's activity.
func (t procTable) begin(pid uint32, o occupant) {
	hist := t[pid]
	for i := range hist {
		if hist[i].live() {
			hist[i].end = o.start
			hist[i].closed = true
		}
	}
	// A duplicate start for the same process (ETW can repeat one across a
	// rundown) must not create a second tenure.
	if n := len(hist); n > 0 && o.key != 0 && hist[n-1].key == o.key {
		hist[n-1].node = o.node
		if o.image != "" {
			hist[n-1].image = o.image
		}
		hist[n-1].end = time.Time{}
		hist[n-1].closed = false
		t[pid] = hist
		return
	}
	t[pid] = append(hist, o)
}

// end closes the live tenure of a PID.
func (t procTable) end(pid uint32, at time.Time) {
	hist := t[pid]
	for i := range hist {
		if hist[i].live() {
			hist[i].end = at
			hist[i].closed = true
		}
	}
	t[pid] = hist
}

// at resolves which process held a PID at a given instant.
//
// This is the question the old code never asked. It kept a single "current"
// pointer per PID, so an event that arrived late — and ETW delivers nothing in
// causal order — was attributed to whoever happened to hold the number by then.
// That is how one program's file writes ended up recorded against another's
// history.
func (t procTable) at(pid uint32, when time.Time) (occupant, bool) {
	hist := t[pid]
	if len(hist) == 0 {
		return occupant{}, false
	}
	if !when.IsZero() {
		// Newest first: an event usually belongs to the current tenure, and
		// this way a stale interval is only consulted when it genuinely covers
		// the instant.
		for i := len(hist) - 1; i >= 0; i-- {
			if hist[i].covers(when) {
				return hist[i], true
			}
		}
		// Before every recorded tenure. This is a process that predates the
		// agent, whose start we therefore never saw; the oldest tenure is the
		// best available answer.
		if when.Before(hist[0].start) {
			return hist[0], true
		}
		return occupant{}, false
	}
	// No timestamp to reason with, so the only safe answer is a tenure that is
	// still open. Falling back to the most recent CLOSED one would re-create
	// the original bug in miniature: attributing an event to a process that had
	// already exited, purely because it was the last thing to hold the number.
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].live() {
			return hist[i], true
		}
	}
	return occupant{}, false
}

// live returns the current occupant of a PID, if one is running.
func (t procTable) liveAt(pid uint32) (occupant, bool) {
	hist := t[pid]
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].live() {
			return hist[i], true
		}
	}
	return occupant{}, false
}

// sameImage compares two image paths when deciding whether a PID changed hands.
//
// Deliberately forgiving. The two sources of an image — an ETW ProcStart and a
// later lookup through the OS — legitimately disagree about case and about how
// the volume is written, a device path such as \Device\HarddiskVolume3\...
// versus C:\..., and treating those as different processes would discard good
// causal links constantly. Only a genuinely different executable counts.
func sameImage(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	return strings.EqualFold(baseName(a), baseName(b))
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
