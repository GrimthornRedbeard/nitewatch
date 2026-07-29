package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/rdap"
	"github.com/threattape/nitewatch/agent/internal/settings"
)

// localReq builds a request that addresses the agent the way a real local
// client does. httptest defaults Host to "example.com", which the DNS-rebinding
// guard correctly rejects.
func localReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader("{}"))
	r.Host = "127.0.0.1:8973"
	return r
}

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
	srv.Handler().ServeHTTP(rr, localReq("GET", "/api/connections?limit=5"))

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
	srv.Handler().ServeHTTP(rr, localReq("GET", "/api/talkers"))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "browser.exe") {
		t.Fatalf("talkers response: %d %s", rr.Code, rr.Body.String())
	}
}

func TestStatusEndpointReflectsSetStatus(t *testing.T) {
	srv := newTestServer(t)
	srv.SetStatus(Status{Source: "live-etw", Running: false, Elevated: false, Message: "need admin"})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, localReq("GET", "/api/status"))
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
		h.ServeHTTP(rr, localReq("POST", path))
		if rr.Code != 403 {
			t.Errorf("%s without the guard header = %d, want 403", path, rr.Code)
		}

		// Header present but the request announces a foreign origin.
		rr = httptest.NewRecorder()
		req := localReq("POST", path)
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
	h.ServeHTTP(rr, localReq("GET", "/api/settings"))
	if rr.Code == 403 {
		t.Error("GET /api/settings must not be blocked by the mutation guard")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, localReq("PUT", "/api/settings"))
	if rr.Code != 403 {
		t.Errorf("PUT /api/settings without the guard header = %d, want 403", rr.Code)
	}
}

// Actions must be re-derived from the stored alert, never taken from the
// request, so a crafted call cannot name an arbitrary process or file.
func TestRunActionRejectsActionsNotOfferedForTheAlert(t *testing.T) {
	srv := newTestServer(t)
	rr := httptest.NewRecorder()
	req := localReq("POST", "/api/actions/run?alert=999&kind=quarantine-file")
	req.Header.Set("X-NiteWatch", "1")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code == 200 {
		t.Fatal("an action for a nonexistent alert must not execute")
	}
}

// Binding 127.0.0.1 does not stop DNS rebinding: an attacker points a hostname
// they control at 127.0.0.1, and the browser then treats their page as
// SAME-ORIGIN with this agent — so CORS never applies and the read endpoints,
// which carry every process path, destination and causal story, are exposed.
// Same-origin GETs send no Origin header, so only a Host check catches this.
func TestForeignHostHeaderIsRejected(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	for _, host := range []string{"evil.example", "evil.example:8973", "127.0.0.1.evil.example:8973"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/connections", nil)
		req.Host = host
		h.ServeHTTP(rr, req)
		if rr.Code != 403 {
			t.Errorf("Host %q = %d, want 403 — the ledger must not be readable via a rebound hostname", host, rr.Code)
		}
	}

	for _, host := range []string{"127.0.0.1:8973", "localhost:8973", "127.0.0.1"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/connections", nil)
		req.Host = host
		h.ServeHTTP(rr, req)
		if rr.Code == 403 {
			t.Errorf("Host %q was rejected; the local dashboard must still work", host)
		}
	}
}

// The lookup endpoint is the only route that reaches the internet. It must not
// be triggerable by anything except a deliberate press of the button.
func TestLookupRequiresPostAndGuard(t *testing.T) {
	var reached int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","name":"TEST-NET"}`))
	}))
	defer up.Close()
	c := rdap.New()
	c.BaseURL = up.URL
	h := newTestServer(t).WithLookups(c).Handler()

	call := func(method, url string, hdr map[string]string) int {
		req := httptest.NewRequest(method, url, nil)
		req.Host = "127.0.0.1:8973"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// A GET — what an <img> or a link would produce — must not query anything.
	if got := call(http.MethodGet, "/api/lookup?q=93.184.216.34", nil); got == http.StatusOK {
		t.Errorf("GET /api/lookup returned 200; a link must not be able to trigger a query")
	}
	// A POST without the header another site cannot set.
	if got := call(http.MethodPost, "/api/lookup?q=93.184.216.34", nil); got != http.StatusForbidden {
		t.Errorf("unguarded POST = %d, want 403", got)
	}
	// A POST from another origin.
	if got := call(http.MethodPost, "/api/lookup?q=93.184.216.34",
		map[string]string{"X-NiteWatch": "1", "Origin": "https://evil.test"}); got != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", got)
	}
	if n := atomic.LoadInt32(&reached); n != 0 {
		t.Fatalf("the registry was contacted %d times by requests that should have been refused", n)
	}

	// The real thing: a guarded POST, as the button sends it.
	if got := call(http.MethodPost, "/api/lookup?q=93.184.216.34",
		map[string]string{"X-NiteWatch": "1"}); got != http.StatusOK {
		t.Errorf("guarded POST = %d, want 200", got)
	}
	if n := atomic.LoadInt32(&reached); n != 1 {
		t.Errorf("registry contacted %d times, want exactly 1", n)
	}
}

// Nothing may query a registry on its own — not on ingest, not on a timer, and
// not while the dashboard is doing its ordinary work.
func TestNoRouteQueriesTheRegistryOnItsOwn(t *testing.T) {
	var reached int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer up.Close()
	c := rdap.New()
	c.BaseURL = up.URL
	h := newTestServer(t).WithLookups(c).Handler()

	for _, path := range []string{
		"/api/connections", "/api/talkers", "/api/status", "/api/alerts",
		"/api/settings", "/api/actions", "/api/process?image=x", "/api/story?id=1", "/",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:8973"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if n := atomic.LoadInt32(&reached); n != 0 {
		t.Fatalf("ordinary dashboard traffic caused %d outbound registry queries; it must cause none", n)
	}
}

// The key must never come back out. A key that is never echoed cannot leak
// through a screenshot, a bug report, or an extension reading the page.
func TestSettingsNeverEchoTheVirusTotalKey(t *testing.T) {
	srv := newTestServer(t)
	dir := t.TempDir()
	led, err := ledger.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()
	st, err := settings.Open(led.SQL(), settings.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	srv = srv.WithSettings(st)
	h := srv.Handler()

	const secret = "sk-not-a-real-virustotal-key-0123456789"
	req := httptest.NewRequest(http.MethodPut, "/api/settings",
		strings.NewReader(`{"virusTotalKey":"`+secret+`","dedupSeconds":300,"retentionDays":90}`))
	req.Host = "127.0.0.1:8973"
	req.Header.Set("X-NiteWatch", "1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("save returned %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Error("the save response echoed the key back")
	}

	get := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	get.Host = "127.0.0.1:8973"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, get)
	if strings.Contains(rec2.Body.String(), secret) {
		t.Errorf("GET /api/settings leaked the key: %s", rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"virusTotalKeySet":true`) {
		t.Errorf("should report that a key is set: %s", rec2.Body.String())
	}

	// Saving again with a blank key must not wipe it — the UI never had the
	// real one to send back.
	req2 := httptest.NewRequest(http.MethodPut, "/api/settings",
		strings.NewReader(`{"virusTotalKey":"","dedupSeconds":300,"retentionDays":90}`))
	req2.Host = "127.0.0.1:8973"
	req2.Header.Set("X-NiteWatch", "1")
	req2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req2)
	if st.Get().VirusTotalKey != secret {
		t.Error("a blank key on save wiped the stored one")
	}
}

// Reputation is the most sensitive thing the agent can do. Nothing automatic
// may reach it, and it must not exist without a key.
func TestReputationIsGuardedAndOffWithoutAKey(t *testing.T) {
	h := newTestServer(t).Handler()
	call := func(method string, hdr map[string]string) int {
		req := httptest.NewRequest(method, "/api/reputation?sha256="+strings.Repeat("a", 64), nil)
		req.Host = "127.0.0.1:8973"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(http.MethodGet, nil); got == http.StatusOK {
		t.Error("a GET must not trigger a reputation query")
	}
	if got := call(http.MethodPost, nil); got != http.StatusForbidden {
		t.Errorf("unguarded POST = %d, want 403", got)
	}
	// Guarded, but no key configured: the feature does not exist.
	if got := call(http.MethodPost, map[string]string{"X-NiteWatch": "1"}); got != http.StatusNotFound {
		t.Errorf("with no key configured = %d, want 404", got)
	}
}

// The dashboard must never be cached.
//
// It is served from an embedded FS whose modtime is zero, so net/http emits
// neither Last-Modified nor ETag. With no validators and no freshness
// directives a browser may keep serving what it has — which is how somebody
// upgrades the agent and still sees the old interface. Worse, the page carries
// this run's API token, so a cached copy is a stale credential in the browser
// cache that will also fail to authenticate after a restart.
func TestDashboardIsNeverCached(t *testing.T) {
	h := newTestServer(t).Handler()
	for _, path := range []string{"/", "/index.html"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:8973"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, rec.Code)
		}
		cc := rec.Header().Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Errorf("%s: Cache-Control = %q, want it to contain no-store", path, cc)
		}
	}
}
