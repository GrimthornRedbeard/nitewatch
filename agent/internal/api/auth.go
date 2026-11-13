// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// Token authenticates callers to the local API.
//
// WHAT THIS DOES AND DOES NOT DO — stated plainly, because overstating a
// security boundary is worse than not having one.
//
// The API listens on loopback HTTP, and any process on the machine can open a
// loopback socket. HTTP cannot identify the process at the other end, so the
// token is the whole check. How a caller can learn it:
//
//   - The dashboard shell served at "/" does NOT contain it. (It used to,
//     which made it free to anyone who asked.)
//   - The agent opens the dashboard at http://127.0.0.1:8973/#t=<token> and
//     prints that link to its console. The fragment is never sent to a
//     server; the page moves it into sessionStorage and removes it from the
//     address bar.
//   - It is written to the api-token file for scripting, with an ACL that
//     admits only SYSTEM and Administrators on Windows (read it from an
//     elevated prompt). A new token is made on every start.
//
// What it therefore stops:
//   - Scripts and malware that probe fixed local ports: a request to "/" no
//     longer yields anything that unlocks /api.
//   - A rebound web page that got past the Host check.
//   - Other user accounts on a shared machine, which can neither read the file
//     nor see the browser that holds the token.
//
// What it does NOT stop: a program already running as the signed-in user. It
// can read the browser's memory, its session storage or its command line, all
// of which are that user's own. Such a program can also read the ledger file
// directly. Remediation stays safe against it for a different reason: the
// elevated agent only acts on records it sealed itself (package seal).
//
// A proper boundary needs an OS-level transport that carries caller identity —
// a named pipe with an ACL on Windows. That is recorded as future work.
type Token struct {
	value string
	path  string
}

// NewToken makes a fresh token for this run and stores it in dir/api-token,
// readable only by SYSTEM and Administrators on Windows (owner-only elsewhere).
//
// A token is never read back from disk. The folder is often user-writable, so
// a token file found there may have been planted by someone who knows its
// value. Failing to write the file is not fatal: the token still works, it
// just cannot be read from disk by scripts this run.
func NewToken(dir string) (*Token, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	t := &Token{value: hex.EncodeToString(raw)}

	path := filepath.Join(dir, "api-token")
	// Remove whatever is there first, then create exclusively. If a link was
	// planted at this name, Remove deletes the link itself and the exclusive
	// create refuses anything recreated in between, so an elevated write
	// cannot be redirected onto another file.
	_ = os.Remove(path)
	if err := writePrivateFile(path, []byte(t.value)); err != nil {
		return t, fmt.Errorf("token not written to %s: %w", path, err)
	}
	t.path = path
	return t, nil
}

// Value is the token string.
func (t *Token) Value() string {
	if t == nil {
		return ""
	}
	return t.value
}

// Path is where the token is stored, for the log line that tells a user where
// to find it if they want to script against the API. Empty when the file could
// not be written.
func (t *Token) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

// matches compares in constant time. The comparison is cheap and the timing
// signal is real when an attacker can make unlimited local requests.
func (t *Token) matches(got string) bool {
	if t == nil || t.value == "" {
		return true // no token configured: authentication disabled
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(t.value)) == 1
}

// requireToken rejects API requests without a valid token. The dashboard shell
// itself is exempt: it carries no data and no credential, and must load so its
// scripts can pick the token up from the URL fragment.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == nil || s.token.Value() == "" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("X-NiteWatch-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if !s.token.matches(got) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
