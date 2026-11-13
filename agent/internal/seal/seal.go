// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package seal authenticates records the agent writes to its own database.
//
// WHY THIS EXISTS. The agent runs elevated, because ETW requires it, and it
// acts on alert and action rows read back from its ledger: "Do this" re-derives
// a remediation from a stored alert, and "Undo" replays a stored undo record.
// The ledger lives beside the exe, often in a folder the signed-in user can
// write, so anything running as that user can insert rows. Without a check,
// such a row directs the elevated process — a file moved into System32, a value
// written into Winlogon.
//
// A seal is an HMAC-SHA256 over the fields the agent later acts on, keyed with
// a secret the unelevated user cannot read. A row the agent did not write
// carries no valid seal, so it is displayed but never acted on. Tampering is
// reduced from "direct the elevated process" to "delete or hide history".
package seal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// KeySize is the length of a sealing key in bytes.
const KeySize = 32

// Key seals and verifies records.
type Key struct {
	k []byte
}

// New wraps an existing key. It must be KeySize bytes.
func New(k []byte) (*Key, error) {
	if len(k) != KeySize {
		return nil, errors.New("seal: key must be 32 bytes")
	}
	return &Key{k: append([]byte(nil), k...)}, nil
}

// Ephemeral returns a fresh key held only in memory. Records sealed with it
// cannot be verified after the process exits, so actions on earlier alerts and
// undo of earlier actions are refused. That is the fallback when no protected
// place to keep a key is available — fail closed, never open.
func Ephemeral() *Key {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; if it ever does,
		// refusing to start is better than sealing with a guessable key.
		panic("seal: no randomness: " + err.Error())
	}
	return &Key{k: b}
}

// Sum returns the seal for an ordered list of fields.
//
// Each field is length-prefixed, so ("ab","c") and ("a","bc") cannot collide.
func (k *Key) Sum(fields ...string) string {
	if k == nil {
		return ""
	}
	m := hmac.New(sha256.New, k.k)
	var n [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write([]byte(f))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// Verify reports whether mac is the seal for fields. An empty mac never
// verifies, which is what rows written before sealing existed carry.
func (k *Key) Verify(mac string, fields ...string) bool {
	if k == nil || mac == "" {
		return false
	}
	got, err := hex.DecodeString(mac)
	if err != nil {
		return false
	}
	want, _ := hex.DecodeString(k.Sum(fields...))
	return hmac.Equal(got, want)
}
