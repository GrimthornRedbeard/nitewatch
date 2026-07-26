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

func TestDedupCollapsesPacketFloodIntoOneRow(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 7, 25, 22, 0, 0, 0, time.UTC)
	// The kernel reports network activity per packet: 200 events, one flow.
	for i := 0; i < 200; i++ {
		err := db.RecordConnectionDedup(Connection{
			Time: base.Add(time.Duration(i) * time.Second), PID: 100, Image: "browser.exe",
			RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "TCP",
		}, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}

	rows, err := db.RecentConnections(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("200 packet events on one flow should collapse to 1 row, got %d", len(rows))
	}
	if rows[0].Events != 200 {
		t.Fatalf("want events=200, got %d", rows[0].Events)
	}
	if !rows[0].LastSeen.After(rows[0].Time) {
		t.Fatalf("last_seen (%v) should advance past first contact (%v)", rows[0].LastSeen, rows[0].Time)
	}
}

func TestDedupSeparatesDistinctFlowsAndExpires(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "dedup2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 7, 25, 22, 0, 0, 0, time.UTC)
	win := time.Minute
	mk := func(ip string, port uint16, at time.Time) Connection {
		return Connection{Time: at, PID: 100, Image: "b.exe", RemoteIP: ip, RemotePort: port, Proto: "TCP"}
	}
	_ = db.RecordConnectionDedup(mk("1.1.1.1", 443, base), win)
	_ = db.RecordConnectionDedup(mk("2.2.2.2", 443, base), win)                    // different host
	_ = db.RecordConnectionDedup(mk("1.1.1.1", 80, base), win)                     // different port
	_ = db.RecordConnectionDedup(mk("1.1.1.1", 443, base.Add(2*time.Minute)), win) // past window

	rows, err := db.RecentConnections(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("distinct flows and expired windows must not collapse; got %d rows", len(rows))
	}
}

func TestDedupBackfillsDomainDiscoveredLater(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "dedup3.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 7, 25, 22, 0, 0, 0, time.UTC)
	c := Connection{Time: base, PID: 100, Image: "b.exe", RemoteIP: "1.1.1.1", RemotePort: 443, Proto: "TCP"}
	_ = db.RecordConnectionDedup(c, time.Minute) // no domain yet (reverse DNS still in flight)

	c.Time = base.Add(time.Second)
	c.Domain = "one.one.one.one" // resolver answered by the next packet
	_ = db.RecordConnectionDedup(c, time.Minute)

	rows, _ := db.RecentConnections(10)
	if len(rows) != 1 || rows[0].Domain != "one.one.one.one" {
		t.Fatalf("late-arriving name should backfill the row: %+v", rows)
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
