package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Token authenticates callers to the local API.
//
// WHAT THIS DOES AND DOES NOT DO — stated plainly, because overstating a
// security boundary is worse than not having one.
//
// The API listens on loopback HTTP, and any process on the machine can open a
// loopback socket. HTTP has no way to identify the process at the other end, so
// this token cannot be a boundary against a local attacker who can read the
// token file: they are running as the same user, and at that point they can
// read the ledger database directly anyway.
//
// What it DOES stop:
//   - Any other user account on a shared machine.
//   - Scripts and malware that probe fixed local ports opportunistically, which
//     is the realistic threat: a stealer that knows nothing about NiteWatch
//     cannot silence its detections or enumerate the user's traffic.
//   - A rebound web page that got past the Host check, since it cannot read a
//     local file to learn the token.
//
// A proper boundary needs an OS-level transport that carries caller identity —
// a named pipe with an ACL on Windows. That is the right long-term answer and
// is recorded as future work; this is the meaningful improvement available
// without changing the transport.
type Token struct {
	value string
	path  string
}

// NewToken loads the token from disk or creates one, storing it owner-readable.
func NewToken(dir string) (*Token, error) {
	path := filepath.Join(dir, "api-token")

	if b, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(b)); len(v) >= 32 {
			return &Token{value: v, path: path}, nil
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	v := hex.EncodeToString(raw)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// 0600: on Windows this maps to an ACL granting only the owner, which is
	// what keeps the token out of reach of other user accounts.
	if err := os.WriteFile(path, []byte(v), 0o600); err != nil {
		return nil, err
	}
	return &Token{value: v, path: path}, nil
}

// Value is the token string.
func (t *Token) Value() string {
	if t == nil {
		return ""
	}
	return t.value
}

// Path is where the token is stored, for the log line that tells a user where
// to find it if they want to script against the API.
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
// itself is exempt: it carries no data and must load in order to present the
// token to the page's own scripts.
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
