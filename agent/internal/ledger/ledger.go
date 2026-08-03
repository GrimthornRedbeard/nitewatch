// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

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

// tsFormat is fixed-width so timestamps compare correctly as strings in SQL.
// RFC3339Nano cannot be used for storage: it strips trailing zeros, so
// "…:29Z" (whole second) sorts ABOVE "…:29.5Z", breaking range comparisons
// like the dedup window's `last_seen >= cutoff`.
const tsFormat = "2006-01-02T15:04:05.000000000Z"

func formatTS(t time.Time) string { return t.UTC().Format(tsFormat) }

func parseTS(s string) time.Time {
	if t, err := time.Parse(tsFormat, s); err == nil {
		return t
	}
	t, _ := time.Parse(time.RFC3339Nano, s) // rows written by older builds
	return t
}

// Connection is one outbound-connection record. Because the kernel reports
// network activity per packet, many raw events collapse into a single row:
// Time is first contact, LastSeen is most recent, Events counts the rollup.
type Connection struct {
	ID         int64
	Time       time.Time
	LastSeen   time.Time
	Events     int
	PID        uint32
	Image      string
	RemoteIP   string
	RemotePort uint16
	Proto      string
	Domain     string
	Verdict    string
	Inbound    bool

	// Offline recon: who owns the address block and where it is registered.
	ASN     uint32
	ASOrg   string
	Country string

	// BytesSent/BytesRecv accumulate across the flow. On an encrypted
	// connection this is the only measure of WHAT moved, and a program that
	// normally downloads suddenly uploading is the shape of exfiltration.
	BytesSent uint64
	BytesRecv uint64

	// Story is the causal chain that produced this connection, serialized from
	// the poset at record time. Kept with the row because the live causal
	// window is bounded — without this the explanation is lost when it rolls.
	Story string
}

// DB wraps the SQLite handle.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if needed) the ledger database at path and applies the
// schema.
func Open(path string) (*DB, error) {
	// The collector writes continuously while the dashboard reads on every
	// refresh, and SQLite's default behaviour under that contention is to fail
	// the reader immediately with "database is locked" — which surfaced as the
	// process view dying with a JSON parse error, because the handler returned
	// that message as plain text.
	//
	//   journal_mode(WAL) lets readers proceed during a write instead of
	//     blocking, which is the actual fix for a read-heavy UI over a
	//     write-heavy recorder.
	//   busy_timeout waits for a lock rather than failing instantly. Five
	//     seconds is far longer than any statement here takes, so in practice
	//     it converts a hard error into a brief wait.
	//   synchronous(NORMAL) is the standard companion to WAL: durable across
	//     application crashes, and we are recording observations, not money.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	h, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A small pool, NOT a serialised one. The comment here used to claim writes
	// were serialised, which this line has never done — and setting it to 1
	// would be the wrong fix. Under WAL a single writer and several readers
	// proceed concurrently, and the writer is already one goroutine (the
	// collector); capping at 1 would instead queue the dashboard's reads behind
	// every write. The cap exists to bound connection count, and busy_timeout
	// covers the brief overlap when a reader meets a checkpoint.
	h.SetMaxOpenConns(4)
	if _, err := h.Exec(schema); err != nil {
		h.Close()
		return nil, err
	}
	if _, err := h.Exec(actionSchema); err != nil {
		h.Close()
		return nil, err
	}
	if _, err := h.Exec(allowSchema); err != nil {
		h.Close()
		return nil, err
	}
	if _, err := h.Exec(alertSchema); err != nil {
		h.Close()
		return nil, err
	}
	return &DB{sql: h}, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// SQL exposes the underlying handle so sibling packages (settings) can share
// one database file rather than opening a second one.
func (d *DB) SQL() *sql.DB { return d.sql }

// RecordConnection inserts one connection row. An empty Verdict defaults to
// "clean" via the schema.
func (d *DB) RecordConnection(c Connection) error {
	return d.RecordConnectionDedup(c, 0)
}

// RecordConnectionDedup records a connection, collapsing it into an existing
// row when the same flow was last seen within window. This is what turns a
// per-packet event firehose into a readable ledger. A zero window disables it.
//
// The flow is keyed on the PROGRAM, not the process instance. Keying on PID
// looked right and was wrong in practice: Chromium-based applications — Claude,
// Discord, Chrome, Brave, Slack, VS Code — run a main process plus a renderer
// per tab plus GPU and utility processes, ALL with the same image name. One app
// talking to one endpoint produced a separate identical-looking row per
// process, which reads exactly like the de-duplication being broken.
//
// Connections we could not attribute fall back to keying on PID, so that
// unrelated unattributed traffic does not all collapse into a single row.
func (d *DB) RecordConnectionDedup(c Connection, window time.Duration) error {
	verdict := c.Verdict
	if verdict == "" {
		verdict = "clean"
	}
	ts := formatTS(c.Time)

	if window > 0 {
		cutoff := formatTS(c.Time.Add(-window))
		var id int64
		var err error
		if c.Image != "" {
			err = d.sql.QueryRow(
				`SELECT id FROM connections
				 WHERE image = ? AND remote_ip = ? AND remote_port = ? AND proto = ?
				   AND last_seen >= ?
				 ORDER BY id DESC LIMIT 1`,
				c.Image, c.RemoteIP, c.RemotePort, c.Proto, cutoff,
			).Scan(&id)
		} else {
			err = d.sql.QueryRow(
				`SELECT id FROM connections
				 WHERE image = '' AND pid = ? AND remote_ip = ? AND remote_port = ? AND proto = ?
				   AND last_seen >= ?
				 ORDER BY id DESC LIMIT 1`,
				c.PID, c.RemoteIP, c.RemotePort, c.Proto, cutoff,
			).Scan(&id)
		}
		if err == nil {
			// Existing flow: bump activity, and fill in a name/image if this
			// event knows one the original row lacked.
			_, err = d.sql.Exec(
				`UPDATE connections
				 SET last_seen = ?, events = events + 1,
				     pid = ?,
				     domain = COALESCE(NULLIF(domain, ''), ?),
				     image  = CASE WHEN image = '' THEN ? ELSE image END,
				     inbound = CASE WHEN ? = 0 THEN 0 ELSE inbound END,
				     asn     = CASE WHEN asn = 0 THEN ? ELSE asn END,
				     as_org  = COALESCE(NULLIF(as_org, ''), ?),
				     country = COALESCE(NULLIF(country, ''), ?),
				     story   = COALESCE(NULLIF(story, ''), ?),
				     bytes_sent = bytes_sent + ?,
				     bytes_recv = bytes_recv + ?
				 WHERE id = ?`,
				ts, c.PID, nullable(c.Domain), c.Image, c.Inbound,
				c.ASN, nullable(c.ASOrg), nullable(c.Country), nullable(c.Story),
				c.BytesSent, c.BytesRecv, id,
			)
			return err
		}
		if err != sql.ErrNoRows {
			return err
		}
	}

	// bytes_sent/bytes_recv belong in this list. They were missing, and the
	// driver accepted the two surplus arguments rather than rejecting the
	// statement, so every flow's FIRST sighting recorded zero bytes. Only
	// repeat sightings had a volume, because the UPDATE branch above adds to
	// the column correctly — which made the bug look like "quiet connections
	// show nothing" instead of what it was.
	_, err := d.sql.Exec(
		`INSERT INTO connections (ts, last_seen, events, pid, image, remote_ip, remote_port, proto, domain, verdict, inbound, asn, as_org, country, story, bytes_sent, bytes_recv)
		 VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, ts, c.PID, c.Image, c.RemoteIP,
		c.RemotePort, c.Proto, nullable(c.Domain), verdict, c.Inbound,
		c.ASN, nullable(c.ASOrg), nullable(c.Country), nullable(c.Story),
		c.BytesSent, c.BytesRecv,
	)
	return err
}

// RecentConnections returns up to limit connections, newest first.
func (d *DB) RecentConnections(limit int) ([]Connection, error) {
	rows, err := d.sql.Query(
		`SELECT ts, COALESCE(NULLIF(last_seen, ''), ts), events, pid, image,
		        remote_ip, remote_port, proto, COALESCE(domain, ''), verdict, inbound,
		        asn, COALESCE(as_org, ''), COALESCE(country, ''), COALESCE(story, ''), id,
		        bytes_sent, bytes_recv
		 FROM connections ORDER BY last_seen DESC, id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanConnections(rows)
}

func scanConnections(rows *sql.Rows) ([]Connection, error) {
	var out []Connection
	for rows.Next() {
		var c Connection
		var ts, last string
		if err := rows.Scan(&ts, &last, &c.Events, &c.PID, &c.Image, &c.RemoteIP,
			&c.RemotePort, &c.Proto, &c.Domain, &c.Verdict, &c.Inbound,
			&c.ASN, &c.ASOrg, &c.Country, &c.Story, &c.ID,
			&c.BytesSent, &c.BytesRecv); err != nil {
			return nil, err
		}
		c.Time = parseTS(ts)
		c.LastSeen = parseTS(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Prune deletes history older than the retention window.
//
// This exists because the dashboard exposed a "keep history for N days"
// setting that nothing enforced: it was clamped, persisted, and then ignored
// while the ledger grew forever. A visible control that does nothing is worse
// than no control — the user believes their data is being aged out.
//
// Alerts and the action audit log are deliberately kept LONGER than
// connections: they are the record of what this software told someone and what
// it did to their machine, and that record is the product's accountability.
func (d *DB) Prune(retention time.Duration, now time.Time) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := formatTS(now.Add(-retention))

	res, err := d.sql.Exec(`DELETE FROM connections WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()

	// Acknowledged alerts age out at four times the connection retention;
	// unacknowledged ones are never deleted, because an unread warning is
	// exactly the thing a user needs to find later.
	alertCutoff := formatTS(now.Add(-4 * retention))
	if _, err := d.sql.Exec(
		`DELETE FROM alerts WHERE status = 'acknowledged' AND ts < ?`, alertCutoff); err != nil {
		return n, err
	}
	return n, nil
}

// ConnectionsForImage returns every recorded flow for one program, newest
// first. This is the backbone of the process view: a program's whole network
// footprint in one place, rather than scattered across a table sorted by time.
func (d *DB) ConnectionsForImage(image string, limit int) ([]Connection, error) {
	rows, err := d.sql.Query(
		`SELECT ts, COALESCE(NULLIF(last_seen, ''), ts), events, pid, image,
		        remote_ip, remote_port, proto, COALESCE(domain, ''), verdict, inbound,
		        asn, COALESCE(as_org, ''), COALESCE(country, ''), COALESCE(story, ''), id,
		        bytes_sent, bytes_recv
		 FROM connections WHERE image = ? ORDER BY last_seen DESC, id DESC LIMIT ?`,
		image, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanConnections(rows)
}

// AlertsForImage returns alerts naming a program, so its history is visible
// from the same place as its traffic.
func (d *DB) AlertsForImage(image string, limit int) ([]Alert, error) {
	all, err := d.RecentAlerts(500)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, a := range all {
		if p, _ := a.Evidence["ImagePath"].(string); p == image {
			out = append(out, a)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// UnnamedIPs returns distinct remote addresses among recent rows that still
// have no name, so a background pass can try to resolve them.
func (d *DB) UnnamedIPs(limit int) ([]string, error) {
	rows, err := d.sql.Query(
		`SELECT DISTINCT remote_ip FROM connections
		 WHERE domain IS NULL OR domain = ''
		 ORDER BY last_seen DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// SetDomainForIP names every unnamed row for an address. Reverse DNS resolves
// asynchronously, so a flow's packets often finish before the answer arrives;
// this attaches the name once it does.
func (d *DB) SetDomainForIP(ip, domain string) error {
	if ip == "" || domain == "" {
		return nil
	}
	_, err := d.sql.Exec(
		`UPDATE connections SET domain = ?
		 WHERE remote_ip = ? AND (domain IS NULL OR domain = '')`,
		domain, ip,
	)
	return err
}

// ConnectionID returns the id of the most recent row for a flow, so an alert
// can anchor to the connection that triggered it.
func (d *DB) ConnectionID(pid uint32, ip string, port uint16, proto string) (int64, error) {
	var id int64
	err := d.sql.QueryRow(
		`SELECT id FROM connections
		 WHERE pid = ? AND remote_ip = ? AND remote_port = ? AND proto = ?
		 ORDER BY id DESC LIMIT 1`, pid, ip, port, proto).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// StoryFor returns the serialized causal chain stored with a connection.
func (d *DB) StoryFor(id int64) (string, error) {
	var story sql.NullString
	err := d.sql.QueryRow(`SELECT story FROM connections WHERE id = ?`, id).Scan(&story)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return story.String, nil
}

// IsNewDestination reports whether this program has reached this destination
// before — the "first contact" signal that gates most of the noisier rules.
//
// dest may be a domain OR a bare address. Nameless connections store domain as
// SQL NULL, so querying `domain = '203.0.113.9'` could never match one: every
// raw-IP flow read as first contact forever, and the rules that gate on it
// (raw-ip-no-dns, unsigned-outbound) refired on every ledger row. Matching the
// address column as well is what makes that gate real.
func (d *DB) IsNewDestination(image, dest string) bool {
	var n int
	err := d.sql.QueryRow(
		`SELECT COUNT(*) FROM connections
		 WHERE image = ? AND (domain = ? OR (domain IS NULL AND remote_ip = ?))`,
		image, nullable(dest), dest,
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

// Summary counts the whole ledger, not the page of it somebody is looking at.
//
// The dashboard's stat tiles were computed from the rows it had fetched, which
// are capped at a thousand. Past that the numbers stopped moving and nothing
// said why — a counter that plateaus on a round number and does not admit it
// undermines every other number beside it.
type Summary struct {
	Connections  int64 `json:"connections"`
	Programs     int64 `json:"programs"`
	Destinations int64 `json:"destinations"`
	// Events is the number of connection events observed. Higher than
	// Connections, because repeat contact on one flow inside the dedup window
	// collapses into a single row with a counter rather than a new row.
	Events int64 `json:"events"`
	Alerts int64 `json:"alerts"`
}

// Summarise returns whole-ledger totals.
func (d *DB) Summarise() (Summary, error) {
	var s Summary
	err := d.sql.QueryRow(`
		SELECT COUNT(*),
		       COUNT(DISTINCT image),
		       COUNT(DISTINCT COALESCE(NULLIF(domain, ''), remote_ip)),
		       COALESCE(SUM(events), 0)
		FROM connections`).
		Scan(&s.Connections, &s.Programs, &s.Destinations, &s.Events)
	if err != nil {
		return s, err
	}
	// A missing alerts table is not worth failing the whole summary over.
	_ = d.sql.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&s.Alerts)
	return s, nil
}
