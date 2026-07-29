// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package source

import "sync"

// nameCache maps an ETW file key to the path it currently refers to.
//
// Kernel-File names a file once, on the Create event, and then identifies it by
// a FileKey/FileObject on every subsequent read and write. So the name has to
// be remembered and looked up later — and the thing being remembered is a
// KERNEL POINTER, which the operating system reuses the moment the file is
// closed.
//
// That makes this the same hazard as a recycled PID, one layer down, and it
// went wrong in the same direction. The original put() returned early when the
// key already existed, so a Create event announcing that a recycled handle now
// refers to a DIFFERENT file was discarded, and every later read on that handle
// was reported against the previous file. Nothing invalidated on close either,
// so a stale entry could outlive its file indefinitely.
//
// The damage was worse than random because only paths worth alerting on are
// cached at all: the caller filters to user-profile files before calling put.
// The cache therefore contains little BUT credential stores and browser
// databases, so every collision resolved to something alarming. A live machine
// reported five unrelated programs — a game launcher, a WebView host, two
// Electron apps — all "reading your Discord session tokens" within a minute,
// because each had opened some file that inherited a pointer Discord's leveldb
// had used moments earlier.
type nameCache struct {
	mu    sync.Mutex
	max   int
	names map[string]string
	// order is insertion order for eviction. It may hold keys that have since
	// been forgotten; eviction skips those rather than paying to remove them
	// from the middle of a slice on every close.
	order []string
}

func newNameCache(max int) *nameCache {
	return &nameCache{max: max, names: make(map[string]string, max)}
}

// put records that key currently names path, replacing any earlier name.
//
// Last write wins, deliberately. A second Create for a key we already know is
// not a duplicate to be ignored — it is the operating system telling us the
// handle has been reused for something else, which is precisely the event that
// used to be dropped.
func (c *nameCache) put(key, name string) {
	if key == "" || name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.names[key]; exists {
		c.names[key] = name // rebind; its place in the eviction order stands
		return
	}
	c.names[key] = name
	c.order = append(c.order, key)
	c.evict()
}

// forget drops a key, called when the file is closed and the kernel is free to
// hand its pointer to somebody else. Without this a name outlives its file and
// the next holder of the pointer inherits it.
func (c *nameCache) forget(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.names, key)
}

func (c *nameCache) get(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.names[key]
}

// evict trims to the cap, skipping keys already forgotten. Caller holds the lock.
func (c *nameCache) evict() {
	for len(c.names) > c.max && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.names, oldest)
	}
	// Compact the tombstones left behind by forget() so order cannot grow
	// without bound on a machine that opens and closes files all day.
	if len(c.order) > 2*c.max {
		live := c.order[:0]
		for _, k := range c.order {
			if _, ok := c.names[k]; ok {
				live = append(live, k)
			}
		}
		c.order = live
	}
}
