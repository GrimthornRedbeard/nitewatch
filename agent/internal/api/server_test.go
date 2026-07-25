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
