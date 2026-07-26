package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/ledger"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	led, err := ledger.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { led.Close() })
	_ = led.RecordConnection(ledger.Connection{
		Time: time.Now(), PID: 100, Image: "browser.exe",
		RemoteIP: "93.184.216.34", RemotePort: 443, Proto: "TCP", Domain: "cdn.example.net",
	})
	return New(led)
}

func TestConnectionsEndpointReturnsJSON(t *testing.T) {
	srv := newTestServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/connections?limit=5", nil))

	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "cdn.example.net") {
		t.Fatalf("body missing domain: %s", rr.Body.String())
	}
}

func TestTalkersEndpoint(t *testing.T) {
	srv := newTestServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/talkers", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "browser.exe") {
		t.Fatalf("talkers response: %d %s", rr.Code, rr.Body.String())
	}
}

func TestStatusEndpointReflectsSetStatus(t *testing.T) {
	srv := newTestServer(t)
	srv.SetStatus(Status{Source: "live-etw", Running: false, Elevated: false, Message: "need admin"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/status", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "live-etw") || !strings.Contains(body, "need admin") {
		t.Fatalf("status body missing fields: %s", body)
	}
	if !strings.Contains(body, `"running":false`) {
		t.Fatalf("running flag not serialized: %s", body)
	}
}

func TestLoopbackOnlyAddr(t *testing.T) {
	srv := newTestServer(t)
	if !strings.HasPrefix(srv.Addr(), "127.0.0.1:") {
		t.Fatalf("server must bind loopback only, got %q", srv.Addr())
	}
}

// The API binds loopback and has no authentication, which is right for a local
// dashboard — but any web page the user visits can make their browser POST to
// 127.0.0.1, and these endpoints kill processes and move files.
func TestMutatingEndpointsRejectCrossSiteRequests(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	mutating := []string{
		"/api/alerts/ack?id=1",
		"/api/alerts/allow?id=1",
		"/api/actions/run?alert=1&kind=kill-process",
		"/api/actions/undo?id=1",
	}
	for _, path := range mutating {
		// No custom header: a plain cross-origin form POST.
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", path, nil))
		if rr.Code != 403 {
			t.Errorf("%s without the guard header = %d, want 403", path, rr.Code)
		}

		// Header present but the request announces a foreign origin.
		rr = httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("X-NiteWatch", "1")
		req.Header.Set("Origin", "https://evil.example")
		h.ServeHTTP(rr, req)
		if rr.Code != 403 {
			t.Errorf("%s with a foreign Origin = %d, want 403", path, rr.Code)
		}
	}
}

func TestSettingsReadIsAllowedButWriteIsGuarded(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// Reading configuration changes nothing, so the panel must still load.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/settings", nil))
	if rr.Code == 403 {
		t.Error("GET /api/settings must not be blocked by the mutation guard")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("PUT", "/api/settings", strings.NewReader("{}")))
	if rr.Code != 403 {
		t.Errorf("PUT /api/settings without the guard header = %d, want 403", rr.Code)
	}
}

// Actions must be re-derived from the stored alert, never taken from the
// request, so a crafted call cannot name an arbitrary process or file.
func TestRunActionRejectsActionsNotOfferedForTheAlert(t *testing.T) {
	srv := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/actions/run?alert=999&kind=quarantine-file", nil)
	req.Header.Set("X-NiteWatch", "1")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code == 200 {
		t.Fatal("an action for a nonexistent alert must not execute")
	}
}
