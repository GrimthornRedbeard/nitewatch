package ledger

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordAndListAlerts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	a := Alert{
		Time: time.Now(), RuleID: "c2-feed-flagged-connection", Area: "c2",
		Severity: "critical", Title: "invoice.exe is contacting a server known to control malware",
		Narrative: "...", Playbook: []string{"Disconnect", "Scan"},
		ConnID: 7, Evidence: map[string]any{"FeedName": "feodo"},
	}
	created, err := db.RecordAlert(a)
	if err != nil || !created {
		t.Fatalf("first alert should be created: created=%v err=%v", created, err)
	}

	rows, err := db.RecentAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 alert, got %d", len(rows))
	}
	if len(rows[0].Playbook) != 2 || rows[0].Playbook[0] != "Disconnect" {
		t.Errorf("playbook did not round-trip: %+v", rows[0].Playbook)
	}
	if rows[0].Evidence["FeedName"] != "feodo" {
		t.Errorf("evidence did not round-trip: %+v", rows[0].Evidence)
	}
	if rows[0].Status != "new" {
		t.Errorf("status = %q, want new", rows[0].Status)
	}
}

// A rule that matches on every packet of one conversation must alert ONCE.
func TestSameRuleOnSameConnectionAlertsOnce(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "b.db"))
	defer db.Close()

	a := Alert{Time: time.Now(), RuleID: "r1", Area: "c2", Severity: "high",
		Title: "t", Narrative: "n", ConnID: 42}
	created1, _ := db.RecordAlert(a)
	created2, _ := db.RecordAlert(a)
	if !created1 {
		t.Fatal("first should create")
	}
	if created2 {
		t.Fatal("duplicate rule+connection must not create a second alert")
	}

	// A different connection is a genuinely different event.
	a.ConnID = 43
	if created, _ := db.RecordAlert(a); !created {
		t.Fatal("same rule on a different connection should alert")
	}
	rows, _ := db.RecentAlerts(10)
	if len(rows) != 2 {
		t.Fatalf("want 2 alerts, got %d", len(rows))
	}
}

func TestAckAndCount(t *testing.T) {
	db, _ := Open(filepath.Join(t.TempDir(), "c.db"))
	defer db.Close()

	_, _ = db.RecordAlert(Alert{Time: time.Now(), RuleID: "r1", Area: "c2",
		Severity: "high", Title: "t", Narrative: "n", ConnID: 1})
	_, _ = db.RecordAlert(Alert{Time: time.Now(), RuleID: "r2", Area: "c2",
		Severity: "low", Title: "t", Narrative: "n", ConnID: 2})

	if n, _ := db.CountNewAlerts(); n != 2 {
		t.Fatalf("want 2 new, got %d", n)
	}
	rows, _ := db.RecentAlerts(10)
	if err := db.AckAlert(rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.CountNewAlerts(); n != 1 {
		t.Fatalf("want 1 new after ack, got %d", n)
	}
}
