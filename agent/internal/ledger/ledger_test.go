// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

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

// Regression (QA sweep): nameless connections store domain as SQL NULL, so a
// lookup keyed on the IP could never match one. FirstContact was therefore
// permanently true for every raw-IP flow, and the rules gated on it fired again
// on every ledger row — a permanent high-severity alert storm from one
// background agent polling a hardcoded address.
func TestIsNewDestinationMatchesRawIPFlows(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "firstcontact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const image = `C:\App\agent.exe`
	const ip = "203.0.113.9"

	if !db.IsNewDestination(image, ip) {
		t.Fatal("never-seen address should be first contact")
	}
	// A connection with NO name, exactly as the collector records one.
	if err := db.RecordConnection(Connection{
		Time: time.Now(), Image: image, RemoteIP: ip, RemotePort: 443, Proto: "TCP",
	}); err != nil {
		t.Fatal(err)
	}
	if db.IsNewDestination(image, ip) {
		t.Fatal("after recording a nameless flow, the same address must NOT be first contact")
	}
	// Named destinations still work, and other programs are unaffected.
	if !db.IsNewDestination(`C:\Other\other.exe`, ip) {
		t.Error("a different program reaching the same address is still first contact")
	}
	_ = db.RecordConnection(Connection{Time: time.Now(), Image: image,
		RemoteIP: "9.9.9.9", Domain: "named.test", Proto: "TCP"})
	if db.IsNewDestination(image, "named.test") {
		t.Error("named destinations must still be matched by name")
	}
}

// The retention setting was clamped, persisted and then ignored — the ledger
// grew forever while the dashboard claimed otherwise.
func TestPruneEnforcesRetention(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "prune.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	_ = db.RecordConnection(Connection{Time: now.Add(-100 * 24 * time.Hour), Image: "old.exe", RemoteIP: "1.1.1.1"})
	_ = db.RecordConnection(Connection{Time: now.Add(-2 * 24 * time.Hour), Image: "recent.exe", RemoteIP: "2.2.2.2"})

	n, err := db.Prune(90*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	rows, _ := db.RecentConnections(10)
	if len(rows) != 1 || rows[0].Image != "recent.exe" {
		t.Fatalf("wrong row survived: %+v", rows)
	}
}

// An unread warning is exactly what a user needs to find later, so it must
// survive retention even when the connections behind it do not.
func TestPruneKeepsUnacknowledgedAlerts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "prunealerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	ancient := now.Add(-3650 * 24 * time.Hour)
	_, _ = db.RecordAlert(Alert{Time: ancient, RuleID: "unread", Area: "c2",
		Severity: "critical", Title: "t", Narrative: "n", ConnID: 1})
	_, _ = db.RecordAlert(Alert{Time: ancient, RuleID: "seen", Area: "c2",
		Severity: "low", Title: "t", Narrative: "n", ConnID: 2})

	all, _ := db.RecentAlerts(10)
	for _, a := range all {
		if a.RuleID == "seen" {
			_ = db.AckAlert(a.ID)
		}
	}
	if _, err := db.Prune(30*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}

	after, _ := db.RecentAlerts(10)
	if len(after) != 1 || after[0].RuleID != "unread" {
		t.Fatalf("the unacknowledged alert must survive; got %+v", after)
	}
}

// Reported from a live machine: claude.exe appeared as five separate rows to
// api.anthropic.com and the de-duplication looked broken.
//
// It was keying on PID. Chromium-based apps — Claude, Discord, Chrome, Brave,
// Slack, VS Code — run a main process plus a renderer per tab plus GPU and
// utility processes, ALL with the same image name. One app talking to one
// endpoint produced one row PER PROCESS.
func TestElectronAppWithManyPIDsCollapsesToOneRow(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "electron.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 7, 26, 18, 4, 0, 0, time.UTC)
	const image = `C:\Users\k\AppData\Local\Claude\claude.exe`

	// Five renderer/utility processes, same program, same endpoint.
	for i, pid := range []uint32{1200, 3044, 5188, 7712, 9004} {
		if err := db.RecordConnectionDedup(Connection{
			Time: base.Add(time.Duration(i) * 3 * time.Second),
			PID:  pid, Image: image,
			RemoteIP: "2607:6bc0::10", RemotePort: 443, Proto: "TCP",
			Domain: "api.anthropic.com",
		}, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := db.RecentConnections(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("one program to one endpoint should be ONE row, got %d", len(rows))
	}
	if rows[0].Events != 5 {
		t.Errorf("activity should count all five processes, got %d", rows[0].Events)
	}
	// The row must carry a current PID so "stop this program" has a live target.
	if rows[0].PID != 9004 {
		t.Errorf("row should hold the most recent PID, got %d", rows[0].PID)
	}
}

// Collapsing by program must not merge things a user would consider distinct.
func TestDedupStillSeparatesGenuinelyDifferentFlows(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "distinct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 26, 18, 0, 0, 0, time.UTC)
	rec := func(image, ip string, port uint16, proto string) {
		_ = db.RecordConnectionDedup(Connection{
			Time: now, PID: 100, Image: image, RemoteIP: ip, RemotePort: port, Proto: proto,
		}, 5*time.Minute)
	}
	rec(`C:\a\claude.exe`, "2607:6bc0::10", 443, "TCP")
	rec(`C:\a\claude.exe`, "2607:6bc0::10", 443, "UDP")  // QUIC vs TCP
	rec(`C:\a\claude.exe`, "160.79.104.10", 443, "TCP")  // IPv4 vs IPv6 endpoint
	rec(`C:\a\claude.exe`, "2607:6bc0::10", 8443, "TCP") // different port
	rec(`C:\b\other.exe`, "2607:6bc0::10", 443, "TCP")   // different program

	rows, _ := db.RecentConnections(20)
	if len(rows) != 5 {
		t.Fatalf("genuinely different flows must stay separate, got %d rows", len(rows))
	}
}

// Unattributed connections must not all collapse into one meaningless row.
func TestUnattributedConnectionsStillKeyOnPID(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "noimage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	_ = db.RecordConnectionDedup(Connection{Time: now, PID: 111, RemoteIP: "1.1.1.1", RemotePort: 443, Proto: "TCP"}, time.Minute)
	_ = db.RecordConnectionDedup(Connection{Time: now, PID: 222, RemoteIP: "1.1.1.1", RemotePort: 443, Proto: "TCP"}, time.Minute)

	rows, _ := db.RecentConnections(10)
	if len(rows) != 2 {
		t.Fatalf("unattributed traffic from different processes must not merge, got %d", len(rows))
	}
}

// A flow seen exactly once must still record how much moved.
//
// It did not. bytes_sent/bytes_recv were absent from the INSERT column list
// while still being passed as arguments, and the driver accepted the surplus
// rather than rejecting the statement — so the first sighting of every flow
// stored zero. The UPDATE branch adds to the columns correctly, which is what
// hid it: anything contacted repeatedly looked right, and the failure showed
// up only as "quiet connections report no volume".
//
// Volume is the one thing about an encrypted conversation that is always
// visible, and it is what separates a heartbeat from an upload of your
// documents. A one-shot exfiltration is precisely the case that must not
// read as zero.
func TestFirstSightingRecordsItsBytes(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const sent, recv = 41_943_040, 12_288
	now := time.Now()
	if err := db.RecordConnectionDedup(Connection{
		Time: now, PID: 7180, Image: `C:\Temp\sync-helper.exe`,
		RemoteIP: "45.137.22.184", RemotePort: 8443, Proto: "TCP",
		BytesSent: sent, BytesRecv: recv,
	}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}

	rows, err := db.RecentConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].BytesSent != sent || rows[0].BytesRecv != recv {
		t.Errorf("first sighting recorded %d/%d bytes, want %d/%d",
			rows[0].BytesSent, rows[0].BytesRecv, sent, recv)
	}

	// And a second sighting inside the window adds to it rather than replacing.
	if err := db.RecordConnectionDedup(Connection{
		Time: now.Add(time.Second), PID: 7180, Image: `C:\Temp\sync-helper.exe`,
		RemoteIP: "45.137.22.184", RemotePort: 8443, Proto: "TCP",
		BytesSent: 1_000, BytesRecv: 2_000,
	}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	rows, _ = db.RecentConnections(10)
	if len(rows) != 1 {
		t.Fatalf("dedup created a second row: %d rows", len(rows))
	}
	if rows[0].BytesSent != sent+1_000 || rows[0].BytesRecv != recv+2_000 {
		t.Errorf("after dedup: %d/%d, want %d/%d",
			rows[0].BytesSent, rows[0].BytesRecv, sent+1_000, recv+2_000)
	}
}
