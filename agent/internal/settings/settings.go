// Package settings holds the agent's user-editable configuration.
//
// Configuration lives in the ledger database and is edited from the dashboard,
// not passed as command-line flags: a consumer security tool is launched by
// double-click, and options nobody can reach are options nobody has. Flags
// remain as first-run defaults and for scripted use.
//
// Values are read on every connection, so changes take effect immediately —
// no restart, which matters because restarting means losing the live causal
// window.
package settings

import (
	"database/sql"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Values is the full set of user-editable options.
type Values struct {
	// IncludeLocal records LAN/loopback destinations too (noisy; off by default).
	IncludeLocal bool `json:"includeLocal"`
	// ResolveNames enables reverse-DNS naming of destinations.
	ResolveNames bool `json:"resolveNames"`
	// Recon enables the offline address-ownership dataset (owner/country).
	Recon bool `json:"recon"`
	// DedupSeconds is the window over which repeated activity on one flow
	// collapses into a single ledger row.
	DedupSeconds int `json:"dedupSeconds"`
	// RetentionDays bounds how long connection history is kept.
	RetentionDays int `json:"retentionDays"`
	// VirusTotalKey enables the optional reputation check on a program's
	// fingerprint. Empty by default: the feature does not exist until the user
	// supplies their own key, so the account doing the asking is theirs.
	VirusTotalKey string `json:"virusTotalKey"`
	// AcceptedTerms records the version of the pre-release disclaimer the user
	// accepted. Storing the version rather than a boolean means editing the
	// terms re-prompts, instead of relying on consent given to different words.
	AcceptedTerms string `json:"acceptedTerms"`
	// Contributor records that the user says they contribute monthly, which
	// retires the contribution notice permanently. Taken at face value: see
	// internal/tip for why this is not verified.
	Contributor bool `json:"contributor"`
	// TipSnoozedUnix is when the contribution notice was last dismissed. Stored
	// as an instant rather than a counter so the notice is paced by elapsed
	// time, and a user who opens the dashboard forty times in an afternoon sees
	// it once.
	TipSnoozedUnix int64 `json:"tipSnoozedUnix"`
}

// Defaults are the shipped configuration.
func Defaults() Values {
	return Values{
		IncludeLocal:  false,
		ResolveNames:  true,
		Recon:         true,
		DedupSeconds:  300,
		RetentionDays: 90,
	}
}

// Store persists Values and serves concurrent reads from the collector.
type Store struct {
	mu  sync.RWMutex
	cur Values
	db  *sql.DB
}

const schema = `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`

// Open loads settings from the database, seeding any missing key from seed.
// Passing the flag-derived values as seed makes flags act as first-run
// defaults without overriding what the user later chose in the UI.
func Open(db *sql.DB, seed Values) (*Store, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	s := &Store{db: db, cur: seed}

	rows, err := db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stored := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		stored[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.cur = merge(seed, stored)
	return s, s.persist(s.cur)
}

// Get returns the current values.
func (s *Store) Get() Values {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Set validates, applies, and persists new values.
func (s *Store) Set(v Values) error {
	v = sanitize(v)
	s.mu.Lock()
	s.cur = v
	s.mu.Unlock()
	return s.persist(v)
}

// DedupWindow is the collapsing window as a duration.
func (s *Store) DedupWindow() time.Duration {
	return time.Duration(s.Get().DedupSeconds) * time.Second
}

func (s *Store) persist(v Values) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, val := range map[string]string{
		"includeLocal":   b2s(v.IncludeLocal),
		"resolveNames":   b2s(v.ResolveNames),
		"recon":          b2s(v.Recon),
		"dedupSeconds":   strconv.Itoa(v.DedupSeconds),
		"retentionDays":  strconv.Itoa(v.RetentionDays),
		"virusTotalKey":  strings.TrimSpace(v.VirusTotalKey),
		"acceptedTerms":  strings.TrimSpace(v.AcceptedTerms),
		"contributor":    b2s(v.Contributor),
		"tipSnoozedUnix": strconv.FormatInt(v.TipSnoozedUnix, 10),
	} {
		if _, err := tx.Exec(
			`INSERT INTO settings (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, val,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func merge(base Values, stored map[string]string) Values {
	out := base
	if v, ok := stored["includeLocal"]; ok {
		out.IncludeLocal = v == "1"
	}
	if v, ok := stored["resolveNames"]; ok {
		out.ResolveNames = v == "1"
	}
	if v, ok := stored["recon"]; ok {
		out.Recon = v == "1"
	}
	if v, ok := stored["dedupSeconds"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			out.DedupSeconds = n
		}
	}
	if v, ok := stored["retentionDays"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			out.RetentionDays = n
		}
	}
	if v, ok := stored["virusTotalKey"]; ok {
		out.VirusTotalKey = v
	}
	if v, ok := stored["acceptedTerms"]; ok {
		out.AcceptedTerms = v
	}
	if v, ok := stored["contributor"]; ok {
		out.Contributor = v == "1"
	}
	if v, ok := stored["tipSnoozedUnix"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			out.TipSnoozedUnix = n
		}
	}
	return sanitize(out)
}

// sanitize clamps values a user could otherwise set to something harmful —
// a zero dedup window would flood the ledger, an unbounded one would merge
// unrelated conversations.
func sanitize(v Values) Values {
	if v.DedupSeconds < 1 {
		v.DedupSeconds = 1
	}
	if v.DedupSeconds > 3600 {
		v.DedupSeconds = 3600
	}
	if v.RetentionDays < 1 {
		v.RetentionDays = 1
	}
	if v.RetentionDays > 3650 {
		v.RetentionDays = 3650
	}
	return v
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
