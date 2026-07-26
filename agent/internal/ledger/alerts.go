package ledger

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Alert is a rendered detection: the words a user reads, plus the evidence that
// justifies them.
//
// Alerts are stored fully rendered rather than re-derived on read. The rule pack
// that produced an alert can change or be removed, and the causal window that
// explained it is bounded — an alert must still say exactly what it said when
// it fired. That is also what makes the record auditable.
type Alert struct {
	ID        int64
	Time      time.Time
	RuleID    string
	Area      string
	Severity  string
	Title     string
	Narrative string
	Playbook  []string
	// ConnID links back to the connection that triggered it, so the UI can show
	// the destination, owner, country and causal story already recorded there.
	ConnID   int64
	Evidence map[string]any
	Status   string // new | acknowledged
}

const alertSchema = `
CREATE TABLE IF NOT EXISTS alerts (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        TEXT NOT NULL,
	rule_id   TEXT NOT NULL,
	area      TEXT NOT NULL,
	severity  TEXT NOT NULL,
	title     TEXT NOT NULL,
	narrative TEXT NOT NULL,
	playbook  TEXT NOT NULL DEFAULT '[]',
	conn_id   INTEGER NOT NULL DEFAULT 0,
	evidence  TEXT NOT NULL DEFAULT '{}',
	status    TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
-- One alert per rule per connection: a rule that matches on every packet of a
-- conversation must not produce an alert per packet.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(rule_id, conn_id);
`

const allowSchema = `
CREATE TABLE IF NOT EXISTS allowlist (
	key   TEXT PRIMARY KEY,
	ts    TEXT NOT NULL,
	label TEXT NOT NULL DEFAULT ''
);`

const actionSchema = `
CREATE TABLE IF NOT EXISTS actions (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts       TEXT NOT NULL,
	alert_id INTEGER NOT NULL,
	kind     TEXT NOT NULL,
	label    TEXT NOT NULL,
	params   TEXT NOT NULL DEFAULT '{}',
	ok       INTEGER NOT NULL DEFAULT 0,
	message  TEXT NOT NULL DEFAULT '',
	undo     TEXT NOT NULL DEFAULT '{}',
	undone   INTEGER NOT NULL DEFAULT 0
);`

// ActionRecord is one remediation the user chose, and what it did.
//
// Recorded whether it SUCCEEDED OR FAILED. A record only of successes would
// hide exactly the case a user needs explained: "I clicked the button and
// nothing happened."
type ActionRecord struct {
	ID      int64
	Time    time.Time
	AlertID int64
	Kind    string
	Label   string
	Params  map[string]string
	OK      bool
	Message string
	Undo    map[string]string
	Undone  bool
}

// RecordAction appends to the action audit log and returns its id.
func (d *DB) RecordAction(a ActionRecord) (int64, error) {
	params, _ := json.Marshal(a.Params)
	undo, _ := json.Marshal(a.Undo)
	res, err := d.sql.Exec(
		`INSERT INTO actions (ts, alert_id, kind, label, params, ok, message, undo, undone)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		formatTS(a.Time), a.AlertID, a.Kind, a.Label, string(params), a.OK, a.Message, string(undo))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RecentActions returns the audit log, newest first.
func (d *DB) RecentActions(limit int) ([]ActionRecord, error) {
	rows, err := d.sql.Query(
		`SELECT id, ts, alert_id, kind, label, params, ok, message, undo, undone
		 FROM actions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionRecord
	for rows.Next() {
		var a ActionRecord
		var ts, params, undo string
		if err := rows.Scan(&a.ID, &ts, &a.AlertID, &a.Kind, &a.Label,
			&params, &a.OK, &a.Message, &undo, &a.Undone); err != nil {
			return nil, err
		}
		a.Time = parseTS(ts)
		_ = json.Unmarshal([]byte(params), &a.Params)
		_ = json.Unmarshal([]byte(undo), &a.Undo)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ActionByID fetches one audit entry, for undo.
func (d *DB) ActionByID(id int64) (ActionRecord, error) {
	all, err := d.RecentActions(1000)
	if err != nil {
		return ActionRecord{}, err
	}
	for _, a := range all {
		if a.ID == id {
			return a, nil
		}
	}
	return ActionRecord{}, sql.ErrNoRows
}

// MarkUndone records that an action was reversed.
func (d *DB) MarkUndone(id int64) error {
	_, err := d.sql.Exec(`UPDATE actions SET undone = 1 WHERE id = ?`, id)
	return err
}

// AddAllow persists a user's "always allow" decision.
func (d *DB) AddAllow(key, label string, at time.Time) error {
	_, err := d.sql.Exec(
		`INSERT INTO allowlist (key, ts, label) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO NOTHING`, key, formatTS(at), label)
	return err
}

// Allows returns every persisted allow key, so decisions survive restarts.
func (d *DB) Allows() ([]string, error) {
	rows, err := d.sql.Query(`SELECT key FROM allowlist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// AlertByID fetches one alert, used when acting on it.
func (d *DB) AlertByID(id int64) (Alert, error) {
	rows, err := d.RecentAlerts(1000)
	if err != nil {
		return Alert{}, err
	}
	for _, a := range rows {
		if a.ID == id {
			return a, nil
		}
	}
	return Alert{}, sql.ErrNoRows
}

// RecordAlert stores an alert, ignoring a repeat of the same rule on the same
// connection. Returns whether a new alert was created.
func (d *DB) RecordAlert(a Alert) (bool, error) {
	playbook, _ := json.Marshal(a.Playbook)
	evidence, _ := json.Marshal(a.Evidence)
	res, err := d.sql.Exec(
		`INSERT OR IGNORE INTO alerts
		   (ts, rule_id, area, severity, title, narrative, playbook, conn_id, evidence, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')`,
		formatTS(a.Time), a.RuleID, a.Area, a.Severity, a.Title, a.Narrative,
		string(playbook), a.ConnID, string(evidence),
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RecentAlerts returns up to limit alerts, newest first.
func (d *DB) RecentAlerts(limit int) ([]Alert, error) {
	rows, err := d.sql.Query(
		`SELECT id, ts, rule_id, area, severity, title, narrative, playbook, conn_id, evidence, status
		 FROM alerts ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Alert
	for rows.Next() {
		var a Alert
		var ts, playbook, evidence string
		if err := rows.Scan(&a.ID, &ts, &a.RuleID, &a.Area, &a.Severity, &a.Title,
			&a.Narrative, &playbook, &a.ConnID, &evidence, &a.Status); err != nil {
			return nil, err
		}
		a.Time = parseTS(ts)
		_ = json.Unmarshal([]byte(playbook), &a.Playbook)
		_ = json.Unmarshal([]byte(evidence), &a.Evidence)
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountNewAlerts is the badge number for the tray/dashboard.
func (d *DB) CountNewAlerts() (int, error) {
	var n int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM alerts WHERE status = 'new'`).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// AckAlert marks an alert as seen.
func (d *DB) AckAlert(id int64) error {
	_, err := d.sql.Exec(`UPDATE alerts SET status = 'acknowledged' WHERE id = ?`, id)
	return err
}
