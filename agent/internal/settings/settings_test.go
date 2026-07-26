package settings

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDefaultsSeedOnFirstRun(t *testing.T) {
	s, err := Open(openDB(t), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if got.IncludeLocal || !got.ResolveNames || !got.Recon || got.DedupSeconds != 300 {
		t.Fatalf("unexpected defaults: %+v", got)
	}
}

// A change made in the UI must survive a restart, and must NOT be clobbered by
// the flag-derived seed on the next launch.
func TestStoredValuesSurviveRestartAndBeatSeed(t *testing.T) {
	db := openDB(t)

	s, err := Open(db, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	v := s.Get()
	v.IncludeLocal = true
	v.ResolveNames = false
	v.DedupSeconds = 60
	if err := s.Set(v); err != nil {
		t.Fatal(err)
	}

	// Restart with defaults as the seed: stored values must win.
	s2, err := Open(db, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Get()
	if !got.IncludeLocal {
		t.Error("includeLocal should have persisted as true")
	}
	if got.ResolveNames {
		t.Error("resolveNames should have persisted as false")
	}
	if got.DedupSeconds != 60 {
		t.Errorf("dedupSeconds = %d, want 60", got.DedupSeconds)
	}
}

func TestSanitizeClampsHarmfulValues(t *testing.T) {
	s, err := Open(openDB(t), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	v := s.Get()
	v.DedupSeconds = 0 // would flood the ledger with a row per packet
	v.RetentionDays = -5
	if err := s.Set(v); err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if got.DedupSeconds < 1 {
		t.Errorf("dedupSeconds not clamped: %d", got.DedupSeconds)
	}
	if got.RetentionDays < 1 {
		t.Errorf("retentionDays not clamped: %d", got.RetentionDays)
	}

	v = got
	v.DedupSeconds = 999999 // would merge unrelated conversations
	_ = s.Set(v)
	if s.Get().DedupSeconds > 3600 {
		t.Errorf("upper bound not clamped: %d", s.Get().DedupSeconds)
	}
}

func TestDedupWindowDuration(t *testing.T) {
	s, _ := Open(openDB(t), Defaults())
	if got := s.DedupWindow().Seconds(); got != 300 {
		t.Fatalf("window = %v s, want 300", got)
	}
}
