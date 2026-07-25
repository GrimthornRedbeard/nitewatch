package ledger

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordAndQueryConnections(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = db.RecordConnection(Connection{
		Time: time.Now(), PID: 100, Image: "browser.exe",
		RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "TCP", Domain: "cdn.example.net",
	})
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.RecentConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Domain != "cdn.example.net" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if rows[0].Verdict != "clean" {
		t.Fatalf("default verdict should be clean, got %q", rows[0].Verdict)
	}
}

func TestIsNewDestination(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	c := Connection{Time: time.Now(), PID: 1, Image: "a.exe", RemoteIP: "1.1.1.1", Domain: "x.test"}
	if !db.IsNewDestination(c.Image, c.Domain) {
		t.Fatal("first sighting should be new")
	}
	if err := db.RecordConnection(c); err != nil {
		t.Fatal(err)
	}
	if db.IsNewDestination(c.Image, c.Domain) {
		t.Fatal("second sighting should not be new")
	}
	if !db.IsNewDestination("other.exe", "x.test") {
		t.Fatal("same domain, different process should be new")
	}
}

func TestRecentConnectionsNewestFirst(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	_ = db.RecordConnection(Connection{Time: base, Image: "old.exe", RemoteIP: "1.1.1.1"})
	_ = db.RecordConnection(Connection{Time: base.Add(time.Minute), Image: "new.exe", RemoteIP: "2.2.2.2"})

	rows, err := db.RecentConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Image != "new.exe" {
		t.Fatalf("expected newest-first ordering, got %+v", rows)
	}
}
