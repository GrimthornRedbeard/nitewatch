// Package ledger is the persistent network flight recorder: every outbound
// connection, with the process and resolved domain behind it, stored in a
// pure-Go SQLite database (no CGO, keeping the single-static-exe promise).
package ledger

import (
	"database/sql"
	_ "embed"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// Connection is one outbound-connection record.
type Connection struct {
	Time       time.Time
	PID        uint32
	Image      string
	RemoteIP   string
	RemotePort uint16
	Proto      string
	Domain     string
	Verdict    string
}

// DB wraps the SQLite handle.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if needed) the ledger database at path and applies the
// schema.
func Open(path string) (*DB, error) {
	h, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := h.Exec(schema); err != nil {
		h.Close()
		return nil, err
	}
	return &DB{sql: h}, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// RecordConnection inserts one connection row. An empty Verdict defaults to
// "clean" via the schema.
func (d *DB) RecordConnection(c Connection) error {
	verdict := c.Verdict
	if verdict == "" {
		verdict = "clean"
	}
	_, err := d.sql.Exec(
		`INSERT INTO connections (ts, pid, image, remote_ip, remote_port, proto, domain, verdict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Time.UTC().Format(time.RFC3339Nano), c.PID, c.Image, c.RemoteIP,
		c.RemotePort, c.Proto, nullable(c.Domain), verdict,
	)
	return err
}

// RecentConnections returns up to limit connections, newest first.
func (d *DB) RecentConnections(limit int) ([]Connection, error) {
	rows, err := d.sql.Query(
		`SELECT ts, pid, image, remote_ip, remote_port, proto, COALESCE(domain, ''), verdict
		 FROM connections ORDER BY ts DESC, id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		var ts string
		if err := rows.Scan(&ts, &c.PID, &c.Image, &c.RemoteIP, &c.RemotePort, &c.Proto, &c.Domain, &c.Verdict); err != nil {
			return nil, err
		}
		c.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, c)
	}
	return out, rows.Err()
}

// IsNewDestination reports whether this (image, domain) pair has never been
// recorded before — the "first time this program contacted this domain" signal.
func (d *DB) IsNewDestination(image, domain string) bool {
	var n int
	err := d.sql.QueryRow(
		`SELECT COUNT(*) FROM connections WHERE image = ? AND domain = ?`,
		image, nullable(domain),
	).Scan(&n)
	if err != nil {
		return false
	}
	return n == 0
}

// nullable maps "" to SQL NULL so domain-less connections don't collide on "".
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
