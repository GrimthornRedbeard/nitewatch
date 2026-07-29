// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package source

import "testing"

// The bug that produced "five different programs are reading your Discord
// session tokens" on a real machine overnight.
//
// A file key is a kernel pointer. Discord opens its leveldb, the pointer is
// cached against that path, Discord closes the file, and the kernel hands the
// same pointer to whatever opens next. The Create event announcing the new
// file was discarded because the key was already known, so every read on the
// recycled handle was reported against Discord's credential store.
func TestRecycledKeyTakesTheNewName(t *testing.T) {
	c := newNameCache(64)
	const key = "0xFFFF8A0B12345678"

	c.put(key, `C:\Users\k\AppData\Roaming\discord\Local Storage\leveldb\007244.log`)
	if got := c.get(key); got == "" {
		t.Fatal("first name was not recorded")
	}

	// The same pointer, now some other program's file.
	const reused = `C:\Users\k\AppData\Roaming\Zoom\data\WebviewCacheX64\cache.db`
	c.put(key, reused)

	if got := c.get(key); got != reused {
		t.Errorf("key still resolves to %q\nwant %q\n"+
			"A second Create for a known key is the OS saying the handle was "+
			"reused, not a duplicate to ignore.", got, reused)
	}
}

// Closing a file must release the name, because the pointer becomes available
// the moment it happens and the next holder must not inherit it.
func TestForgetReleasesTheName(t *testing.T) {
	c := newNameCache(64)
	const key = "0xDEADBEEF"
	c.put(key, `C:\Users\k\AppData\Roaming\discord\Local Storage\leveldb\007239.ldb`)
	c.forget(key)
	if got := c.get(key); got != "" {
		t.Errorf("name survived the close: %q — the next file to get this "+
			"pointer would be reported as Discord's credential store", got)
	}
}

// An unknown key must resolve to nothing rather than to somebody else's file.
// The caller drops events it cannot name, so a miss is a gap; a wrong hit is a
// false accusation against a named program.
func TestUnknownKeyResolvesToNothing(t *testing.T) {
	c := newNameCache(8)
	if got := c.get("never-seen"); got != "" {
		t.Errorf("unknown key resolved to %q", got)
	}
}

func TestEvictionKeepsTheCacheBounded(t *testing.T) {
	const max = 32
	c := newNameCache(max)
	for i := 0; i < max*4; i++ {
		c.put(string(rune('a'+i%26))+string(rune('0'+i/26)), "C:\\Users\\k\\f")
	}
	c.mu.Lock()
	n, ord := len(c.names), len(c.order)
	c.mu.Unlock()
	if n > max {
		t.Errorf("cache holds %d entries, cap is %d", n, max)
	}
	if ord > 2*max {
		t.Errorf("eviction order grew to %d with a cap of %d", ord, max)
	}
}

// forget() leaves a tombstone in the eviction order; a machine opening and
// closing files all day must not accumulate them without bound.
func TestForgottenKeysDoNotGrowTheOrderForever(t *testing.T) {
	c := newNameCache(16)
	for i := 0; i < 5000; i++ {
		k := "key" + string(rune(i%128)) + string(rune(i/128))
		c.put(k, `C:\Users\k\file`)
		c.forget(k)
	}
	c.mu.Lock()
	ord := len(c.order)
	c.mu.Unlock()
	if ord > 200 {
		t.Errorf("eviction order grew to %d entries from repeated open/close", ord)
	}
}

// The overnight incident, start to finish.
//
// Discord's leveldb churns files constantly, so its paths are the ones most
// often in the cache — and because the caller only caches paths worth alerting
// on, they are nearly the only thing in it. Whatever inherits one of those
// pointers gets accused of reading session tokens.
func TestTheOvernightFalseAccusation(t *testing.T) {
	c := newNameCache(256)
	const handle = "0xFFFFC00E1A2B3C40" // one kernel pointer, three tenants

	discord := `C:\Users\kstal\AppData\Roaming\discord\Local Storage\leveldb\007244.log`
	c.put(handle, discord)
	c.forget(handle) // Discord closes it; the kernel is now free to reuse it

	// Battle.net's agent opens something of its own and gets the same pointer.
	agent := `C:\Users\kstal\AppData\Roaming\Zoom\data\WebviewCacheX64\cache.db`
	c.put(handle, agent)
	if got := c.get(handle); got != agent {
		t.Fatalf("Agent.exe's read resolves to %q — it would be reported as "+
			"reading Discord's session tokens", got)
	}

	// It closes, and a browser inherits it in turn.
	c.forget(handle)
	brave := `C:\Users\kstal\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies`
	c.put(handle, brave)
	if got := c.get(handle); got != brave {
		t.Fatalf("brave.exe's read resolves to %q, want its own file", got)
	}

	// And once nothing holds it, it names nothing at all.
	c.forget(handle)
	if got := c.get(handle); got != "" {
		t.Errorf("a closed handle still names %q", got)
	}
}
