package ledger

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The collector writes continuously while the dashboard reads on every refresh.
// Without WAL and a busy timeout SQLite fails the reader outright with
// "database is locked" — which reached the user as a JSON parse error, because
// the API returns that message as plain text and the page called .json() on it.
func TestReadsSurviveConcurrentWrites(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const image = `C:\Users\k\AppData\Local\Discord\app-1.0.9249\Discord.exe`
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: the collector recording connections as fast as it can.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = db.RecordConnection(Connection{
				Time: time.Now(), PID: uint32(1000 + i%50), Image: image,
				RemoteIP:   fmt.Sprintf("10.0.%d.%d", i%256, (i/256)%256),
				RemotePort: 443, Proto: "TCP",
			})
		}
	}()

	// Readers: the dashboard refreshing the views that crashed.
	var mu sync.Mutex
	var failures []error
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				if _, err := db.ConnectionsForImage(image, 500); err != nil {
					mu.Lock()
					failures = append(failures, fmt.Errorf("ConnectionsForImage: %w", err))
					mu.Unlock()
				}
				if _, err := db.RecentConnections(200); err != nil {
					mu.Lock()
					failures = append(failures, fmt.Errorf("RecentConnections: %w", err))
					mu.Unlock()
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("timed out — a reader or writer is stuck on a lock")
	}

	if len(failures) > 0 {
		t.Errorf("%d read(s) failed under concurrent writes; first: %v", len(failures), failures[0])
	}
}

// WAL is what lets a reader proceed while a write is in flight. If this
// regresses to the default rollback journal, the test above starts flaking
// rather than failing cleanly, so assert the mode directly.
func TestJournalModeIsWAL(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var mode string
	if err := db.SQL().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want \"wal\"", mode)
	}
}
