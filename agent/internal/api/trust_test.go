// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/respond"
	"github.com/threattape/nitewatch/agent/internal/seal"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// sealLedger configures the ledger the way main does in production.
func sealLedger(t *testing.T, s *Server) {
	t.Helper()
	s.ledger.SetSealer(seal.Ephemeral())
}

// recordingExec stands in for the Windows executor and records whether the
// server asked it to change the machine.
type recordingExec struct {
	mu    sync.Mutex
	runs  []respond.Action
	undos []map[string]string
}

func (e *recordingExec) Execute(a respond.Action) respond.Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runs = append(e.runs, a)
	return respond.Result{OK: true, Message: "done", Undo: map[string]string{"rule": "NiteWatch block " + a.Params["ip"], "ip": a.Params["ip"]}}
}

func (e *recordingExec) Undo(a respond.Action, undo map[string]string) respond.Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.undos = append(e.undos, undo)
	return respond.Result{OK: true, Message: "undone"}
}

func (e *recordingExec) counts() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.runs), len(e.undos)
}

const testQuarantine = `C:\NiteWatch\quarantine`

func post(t *testing.T, h http.Handler, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := localReq(http.MethodPost, target)
	req.Header.Set("X-NiteWatch", "1")
	if token != "" {
		req.Header.Set("X-NiteWatch-Token", token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// R-01. The page anyone can fetch without credentials must not contain the
// credential. It used to: GET / substituted the live token into the HTML, so
// one unauthenticated request unlocked every /api route.
func TestDashboardShellDoesNotCarryTheToken(t *testing.T) {
	tok, err := NewToken(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newTestServer(t).WithToken(tok).Handler()
	for _, path := range []string{"/", "/index.html"} {
		req := localReq(http.MethodGet, path)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, rr.Code)
		}
		if strings.Contains(rr.Body.String(), tok.Value()) {
			t.Fatalf("unauthenticated GET %s returned the API token", path)
		}
	}
	// And the API still refuses a caller that has only fetched the page.
	req := localReq(http.MethodGet, "/api/settings")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("/api/settings without a token = %d, want 401", rr.Code)
	}
}

// R-02. Action rows come back from a database the signed-in user can write,
// and the agent acts on them elevated. A row the agent did not write itself
// must never be undone, however plausible it looks.
func TestForgedUndoRecordsAreRefused(t *testing.T) {
	srv := newTestServer(t)
	sealLedger(t, srv)
	ex := &recordingExec{}
	srv.WithExecutor(ex, testQuarantine)
	h := srv.Handler()

	forged := []struct{ kind, params, undo string }{
		{"quarantine-file", `{"path":"C:\\Users\\k\\Downloads\\x.exe"}`,
			`{"from":"C:\\NiteWatch\\quarantine\\payload.dll","to":"C:\\Windows\\System32\\evil.dll"}`},
		{"remove-autostart", `{"location":"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","name":"Userinit"}`,
			`{"kind":"registry","location":"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","name":"Userinit","value":"C:\\Users\\k\\evil.exe"}`},
	}
	for _, f := range forged {
		res, err := srv.ledger.SQL().Exec(
			`INSERT INTO actions (ts, alert_id, kind, label, params, ok, message, undo, undone)
			 VALUES ('2026-11-13T00:00:00Z', 1, ?, 'x', ?, 1, '', ?, 0)`, f.kind, f.params, f.undo)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		rr := post(t, h, "/api/actions/undo?id="+itoa(id), "")
		if _, undos := ex.counts(); undos != 0 {
			t.Fatalf("%s: a row the agent never wrote was undone (HTTP %d: %s)", f.kind, rr.Code, rr.Body.String())
		}
	}
}

// R-02, the execute half. A forged alert row would otherwise let any local
// process choose what the elevated agent kills, quarantines or deletes.
func TestForgedAlertsCannotDriveActions(t *testing.T) {
	srv := newTestServer(t)
	sealLedger(t, srv)
	ex := &recordingExec{}
	srv.WithExecutor(ex, testQuarantine)
	h := srv.Handler()

	res, err := srv.ledger.SQL().Exec(
		`INSERT INTO alerts (ts, rule_id, area, severity, title, narrative, playbook, conn_id, evidence, status)
		 VALUES ('2026-11-13T00:00:00Z', 'c2-x', 'c2', 'critical', 't', 'n', '[]', 7,
		         '{"ImagePath":"C:\\Program Files\\Vendor\\svc.exe","ProcessName":"svc.exe","PID":"4242","RemoteIP":"1.2.3.4"}', 'new')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	for _, kind := range []string{"block-address", "kill-process", "quarantine-file"} {
		rr := post(t, h, "/api/actions/run?alert="+itoa(id)+"&kind="+kind, "")
		if runs, _ := ex.counts(); runs != 0 {
			t.Fatalf("%s: a forged alert drove an action (HTTP %d: %s)", kind, rr.Code, rr.Body.String())
		}
	}
}

// The positive control for the two tests above: rows the agent wrote itself
// still drive actions and undo. Without this, "nothing ran" would also pass
// if sealing simply broke every action.
func TestSealedRecordsStillWork(t *testing.T) {
	srv := newTestServer(t)
	sealLedger(t, srv)
	ex := &recordingExec{}
	srv.WithExecutor(ex, testQuarantine)
	h := srv.Handler()

	if _, err := srv.ledger.RecordAlert(ledger.Alert{
		Time: time.Now(), RuleID: "c2-x", Area: "c2", Severity: "high", Title: "t", Narrative: "n",
		ConnID: 9, Evidence: map[string]any{"RemoteIP": "1.2.3.4", "Destination": "1.2.3.4"},
	}); err != nil {
		t.Fatal(err)
	}
	alerts, _ := srv.ledger.RecentAlerts(1)
	if len(alerts) != 1 || !alerts[0].Sealed {
		t.Fatalf("the agent's own alert did not read back sealed: %+v", alerts)
	}
	rr := post(t, h, "/api/actions/run?alert="+itoa(alerts[0].ID)+"&kind=block-address", "")
	if runs, _ := ex.counts(); runs != 1 || rr.Code != http.StatusOK {
		t.Fatalf("sealed alert did not drive its action: runs=%d HTTP %d %s", runs, rr.Code, rr.Body.String())
	}

	actions, _ := srv.ledger.RecentActions(1)
	if len(actions) != 1 || !actions[0].Sealed {
		t.Fatalf("the agent's own action did not read back sealed: %+v", actions)
	}
	rr = post(t, h, "/api/actions/undo?id="+itoa(actions[0].ID), "")
	if _, undos := ex.counts(); undos != 1 || rr.Code != http.StatusOK {
		t.Fatalf("sealed action was not undone: undos=%d HTTP %d %s", undos, rr.Code, rr.Body.String())
	}

	// Editing one field of the sealed undo record breaks the seal.
	if _, err := srv.ledger.SQL().Exec(`UPDATE actions SET undo = ? WHERE id = ?`,
		`{"ip":"8.8.8.8","rule":"NiteWatch block 8.8.8.8"}`, actions[0].ID); err != nil {
		t.Fatal(err)
	}
	rr = post(t, h, "/api/actions/undo?id="+itoa(actions[0].ID), "")
	if _, undos := ex.counts(); undos != 1 {
		t.Fatalf("an edited undo record was replayed (HTTP %d %s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "json") {
		t.Errorf("refusal is not JSON, so the dashboard cannot show the reason: %q", rr.Header().Get("Content-Type"))
	}
}

// An alert the agent cannot vouch for is listed with no actions and a reason.
func TestUnsealedAlertOffersNoActions(t *testing.T) {
	srv := newTestServer(t)
	sealLedger(t, srv)
	srv.WithExecutor(&recordingExec{}, testQuarantine)
	res, err := srv.ledger.SQL().Exec(
		`INSERT INTO alerts (ts, rule_id, area, severity, title, narrative, playbook, conn_id, evidence, status)
		 VALUES ('2026-11-13T00:00:00Z', 'c2-x', 'c2', 'high', 't', 'n', '[]', 7, '{"RemoteIP":"1.2.3.4"}', 'new')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, localReq(http.MethodGet, "/api/actions?alert="+itoa(id)))
	body := rr.Body.String()
	if !strings.Contains(body, `"actions":[]`) || !strings.Contains(body, `"unverified":true`) {
		t.Fatalf("unsealed alert offered actions: %s", body)
	}
}

// A token is made fresh on each start and never read back from a file that
// may have been planted; the file is created owner-only, and a link planted at
// its name is replaced rather than written through.
func TestNewTokenIsFreshAndNotWrittenThroughALink(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, "api-token")
	if err := os.WriteFile(planted, []byte(strings.Repeat("a", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	tok, err := NewToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value() == strings.Repeat("a", 64) {
		t.Fatal("a token found on disk was adopted")
	}
	b, _ := os.ReadFile(planted)
	if string(b) != tok.Value() {
		t.Fatal("the token file does not hold this run's token")
	}
	if fi, _ := os.Stat(planted); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v, want 0600", fi.Mode().Perm())
	}

	// A symlink at the token's name must not redirect the write.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(planted)
	if err := os.Symlink(victim, planted); err != nil {
		t.Skip("cannot create symlinks here:", err)
	}
	if _, err := NewToken(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatal("the token was written through a planted link")
	}
}
