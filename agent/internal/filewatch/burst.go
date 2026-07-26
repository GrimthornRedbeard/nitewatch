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
		st = &procState{image: image}
		t.procs[pid] = st
	}
	if st.image == "" {
		st.image = image
	}
	st.updated = at

	cat := Classify(path)
	st.events = append(st.events, fileEvent{
		path:    path,
		at:      at,
		renamed: EncryptedLookingExt(path),
		note:    cat == RansomNote,
	})

	// Drop everything older than the window.
	cutoff := at.Add(-t.window)
	kept := st.events[:0]
	for _, e := range st.events {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	st.events = kept

	return summarize(pid, st)
}

func summarize(pid uint32, st *procState) Burst {
	b := Burst{PID: pid, Image: st.image}
	seen := map[string]bool{}
	dirs := map[string]bool{}
	for _, e := range st.events {
		if !seen[e.path] {
			seen[e.path] = true
			b.Files++
			if len(b.Sample) < 5 {
				b.Sample = append(b.Sample, e.path)
			}
		}
		if e.renamed {
			b.Renamed++
		}
		if e.note {
			b.Notes++
		}
		dirs[dirOf(e.path)] = true
		if b.Oldest.IsZero() || e.at.Before(b.Oldest) {
			b.Oldest = e.at
		}
		if e.at.After(b.Newest) {
			b.Newest = e.at
		}
	}
	b.Dirs = len(dirs)
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
	if b.Notes > 0 && b.Files > 0 {
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
