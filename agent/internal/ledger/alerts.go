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
