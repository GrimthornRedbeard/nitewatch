package filewatch

import (
	"sync"
	"time"
)

// Burst is what a process has done to user files recently.
type Burst struct {
	PID   uint32
	Image string
	// Files is the number of DISTINCT user documents touched in the window.
	// Distinct matters: a program rewriting one file a thousand times is
	// saving; a program touching a thousand files once is encrypting.
	Files int
	// Renamed counts files that gained an encryption-looking extension.
	Renamed int
	// Notes counts ransom-note files dropped.
	Notes int
	// Dirs is how many separate folders were touched — encryption sweeps a
	// tree, ordinary work stays put.
	Dirs   int
	Oldest time.Time
	Newest time.Time
	// Sample carries a few paths for the alert, so the user sees their own
	// filenames rather than a count.
	Sample []string
}

// Tracker maintains a sliding window of file activity per process.
type Tracker struct {
	mu     sync.Mutex
	window time.Duration
	procs  map[uint32]*procState
	// maxTracked bounds memory: a machine under a real encryption sweep
	// generates enormous volume, and running out of memory mid-incident would
	// be the worst possible failure.
	maxTracked int
}

type procState struct {
	image   string
	events  []fileEvent
	updated time.Time
	// summary is maintained incrementally. Recomputing it per event made
	// Record O(n^2): measured 15s for 20k writes, all of it on the single
	// ingest goroutine, so the network ledger stalls during an encryption
	// sweep — losing the exfiltration evidence while counting file writes.
	seen    map[string]int // path -> live event count; makes distinct-file accounting O(1)
	dirs    map[string]int
	files   int
	renamed int
	notes   int
	sample  []string
}

type fileEvent struct {
	path    string
	at      time.Time
	renamed bool
	note    bool
}

// DefaultWindow: encryption sweeps are fast and sustained. A minute is long
// enough to accumulate obvious evidence and short enough that ordinary bursty
// work (a save-all, an unzip) does not accumulate into a false alarm.
const DefaultWindow = 60 * time.Second

func NewTracker() *Tracker {
	return &Tracker{window: DefaultWindow, procs: map[uint32]*procState{}, maxTracked: 256}
}

// Record adds a file write and returns the process's current burst.
func (t *Tracker) Record(pid uint32, image, path string, at time.Time) Burst {
	t.mu.Lock()
	defer t.mu.Unlock()

	st, ok := t.procs[pid]
	if !ok {
		if len(t.procs) >= t.maxTracked {
			t.evictStaleLocked(at)
		}
		st = &procState{image: image, seen: map[string]int{}, dirs: map[string]int{}}
		t.procs[pid] = st
	}
	if st.image == "" {
		st.image = image
	}
	st.updated = at

	ev := fileEvent{
		path:    path,
		at:      at,
		renamed: EncryptedLookingExt(path),
		note:    Classify(path) == RansomNote,
	}
	st.add(ev)

	// Expire from the front; events arrive in time order.
	cutoff := at.Add(-t.window)
	drop := 0
	for drop < len(st.events) && !st.events[drop].at.After(cutoff) {
		st.remove(st.events[drop])
		drop++
	}
	st.events = st.events[drop:]

	// Bound per-process history so one sweep cannot grow without limit.
	if over := len(st.events) - maxEventsPerProc; over > 0 {
		for i := 0; i < over; i++ {
			st.remove(st.events[i])
		}
		st.events = st.events[over:]
	}

	return st.summary(pid)
}

// maxEventsPerProc caps retained events for one process. The window normally
// bounds this, but an encryption sweep can write far faster than the window
// expires; the thresholds are reached long before the cap, so nothing is lost.
const maxEventsPerProc = 4096

func (st *procState) add(e fileEvent) {
	st.events = append(st.events, e)
	if st.seen[e.path] == 0 {
		st.files++
		if len(st.sample) < 5 {
			st.sample = append(st.sample, e.path)
		}
	}
	st.seen[e.path]++
	if e.renamed {
		st.renamed++
	}
	if e.note {
		st.notes++
	}
	st.dirs[dirOf(e.path)]++
}

func (st *procState) remove(e fileEvent) {
	if e.renamed {
		st.renamed--
	}
	if e.note {
		st.notes--
	}
	if d := dirOf(e.path); st.dirs[d] > 1 {
		st.dirs[d]--
	} else {
		delete(st.dirs, d)
	}
	// Distinct-file accounting by refcount: drop the path only when its last
	// event ages out. Scanning the event slice here is what kept Record
	// superlinear even after the summary was made incremental.
	if n := st.seen[e.path]; n > 1 {
		st.seen[e.path] = n - 1
	} else if n == 1 {
		delete(st.seen, e.path)
		st.files--
	}
}

func (st *procState) summary(pid uint32) Burst {
	b := Burst{PID: pid, Image: st.image, Files: st.files,
		Renamed: st.renamed, Notes: st.notes, Dirs: len(st.dirs)}
	b.Sample = append(b.Sample, st.sample...)
	if len(st.events) > 0 {
		b.Oldest = st.events[0].at
		b.Newest = st.events[len(st.events)-1].at
	}
	return b
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}

// evictStaleLocked drops the least recently active processes.
func (t *Tracker) evictStaleLocked(now time.Time) {
	var oldestPID uint32
	var oldest time.Time
	for pid, st := range t.procs {
		if oldest.IsZero() || st.updated.Before(oldest) {
			oldest, oldestPID = st.updated, pid
		}
	}
	delete(t.procs, oldestPID)
}

// Forget drops a process's history, called when it exits.
func (t *Tracker) Forget(pid uint32) {
	t.mu.Lock()
	delete(t.procs, pid)
	t.mu.Unlock()
}

// Thresholds decide when a burst becomes an alert.
//
// These numbers are the false-positive budget made concrete. Set them low and
// every unzip, sync and photo import becomes a ransomware alarm; set them high
// and the warning arrives after the files are gone. They are deliberately
// paired with corroborating signals (renames, notes, spread across folders)
// rather than raised on volume alone.
const (
	// MassWriteFiles: distinct user documents rewritten within the window.
	MassWriteFiles = 40
	// MassWriteDirs: how many folders it must span. Encryption sweeps a tree;
	// ordinary bulk work usually stays in one place.
	MassWriteDirs = 3
	// ConfirmedRenames: encryption-looking renames that, combined with volume,
	// remove reasonable doubt.
	ConfirmedRenames = 10
	// NoteCorroboration: how many OTHER user files must have been touched
	// alongside a ransom note before it counts as confirmation.
	NoteCorroboration = 5
)

// Verdict grades a burst.
type Verdict int

const (
	Nothing Verdict = iota
	// Suspicious is a burst worth warning about but explainable by ordinary
	// bulk file work.
	Suspicious
	// Confirmed carries corroboration: renames or a ransom note.
	Confirmed
)

// Assess grades a burst without knowing anything about the process. Callers
// layer trust (signature, publisher) on top.
func Assess(b Burst) Verdict {
	// A ransom note CORROBORATES encryption; it does not prove it alone.
	// Ransomware encrypts first and then leaves the note, so a note with no
	// accompanying file activity is just a file that happens to be called
	// readme. Requiring real activity alongside it keeps ordinary documents
	// from raising the loudest alert in the product.
	if b.Notes > 0 && b.Files-b.Notes >= NoteCorroboration {
		return Confirmed
	}
	if b.Renamed >= ConfirmedRenames && b.Files >= ConfirmedRenames {
		return Confirmed
	}
	if b.Files >= MassWriteFiles && b.Dirs >= MassWriteDirs {
		return Suspicious
	}
	return Nothing
}
