// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package ledger

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/seal"
)

// A ledger written by 0.1.8-pre has no mac columns. Opening it must add them,
// and the rows it already held must read back unsealed — they were never
// sealed, so nothing should act on them.
func TestOldLedgerGainsSealColumnsAndOldRowsStayUnsealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	h, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, rule_id TEXT NOT NULL,
		  area TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, narrative TEXT NOT NULL,
		  playbook TEXT NOT NULL DEFAULT '[]', conn_id INTEGER NOT NULL DEFAULT 0,
		  evidence TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'new')`,
		`CREATE TABLE actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_id INTEGER NOT NULL,
		  kind TEXT NOT NULL, label TEXT NOT NULL, params TEXT NOT NULL DEFAULT '{}', ok INTEGER NOT NULL DEFAULT 0,
		  message TEXT NOT NULL DEFAULT '', undo TEXT NOT NULL DEFAULT '{}', undone INTEGER NOT NULL DEFAULT 0)`,
		`INSERT INTO alerts (ts, rule_id, area, severity, title, narrative) VALUES ('2026-10-01T00:00:00Z','r','c2','high','t','n')`,
		`INSERT INTO actions (ts, alert_id, kind, label) VALUES ('2026-10-01T00:00:00Z', 1, 'block-address', 'x')`,
	} {
		if _, err := h.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	h.Close()

	d, err := Open(path)
	if err != nil {
		t.Fatalf("opening a pre-seal ledger: %v", err)
	}
	defer d.Close()
	d.SetSealer(seal.Ephemeral())

	if _, err := d.RecordAlert(Alert{Time: time.Now(), RuleID: "r2", Area: "c2", Severity: "high",
		Title: "t", Narrative: "n", ConnID: 2, Evidence: map[string]any{"RemoteIP": "1.2.3.4"}}); err != nil {
		t.Fatal(err)
	}
	alerts, err := d.RecentAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	sealed := map[string]bool{}
	for _, a := range alerts {
		sealed[a.RuleID] = a.Sealed
	}
	if sealed["r"] || !sealed["r2"] {
		t.Fatalf("sealed = %v, want old row unsealed and new row sealed", sealed)
	}
	acts, err := d.RecentActions(10)
	if err != nil || len(acts) != 1 || acts[0].Sealed {
		t.Fatalf("old action row: %+v err=%v, want one unsealed row", acts, err)
	}
	// Re-opening is idempotent.
	d.Close()
	if d2, err := Open(path); err != nil {
		t.Fatalf("re-open: %v", err)
	} else {
		d2.Close()
	}
}

// With no sealer configured nothing reads back as sealed: closed, not open.
func TestNoSealerMeansNothingIsSealed(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.RecordAlert(Alert{Time: time.Now(), RuleID: "r", Area: "c2", Severity: "high", Title: "t", Narrative: "n"}); err != nil {
		t.Fatal(err)
	}
	a, _ := d.RecentAlerts(1)
	if len(a) != 1 || a[0].Sealed {
		t.Fatalf("alert without a sealer read back sealed: %+v", a)
	}
}
