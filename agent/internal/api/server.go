// Package api exposes the ledger over a loopback-only HTTP+JSON interface for
// the local dashboard. Binding is 127.0.0.1 exclusively — a hard privacy
// constraint, never 0.0.0.0.
package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/respond"
	"github.com/threattape/nitewatch/agent/internal/settings"
)

//go:embed dashboard
var dashboardFS embed.FS

// DefaultAddr is the loopback address the dashboard/API listens on.
const DefaultAddr = "127.0.0.1:8973"

type Server struct {
	ledger        *ledger.DB
	settings      *settings.Store
	suppress      *detect.Suppressor
	exec          respond.Executor
	quarantineDir string
	token         *Token
	addr          string

	mu     sync.RWMutex
	status Status
}

// Status describes the agent's live telemetry state for the dashboard banner.
type Status struct {
	Source   string `json:"source"`   // "live-etw" | "replay" | "none"
	Running  bool   `json:"running"`  // is telemetry actually flowing?
	Elevated bool   `json:"elevated"` // process has admin (live source needs it)
	Message  string `json:"message"`  // human-readable note / error
}

func New(led *ledger.DB) *Server {
	return &Server{ledger: led, addr: DefaultAddr}
}

// WithSuppressor lets the dashboard record "always allow" decisions against the
// same gates the collector consults.
func (s *Server) WithSuppressor(sup *detect.Suppressor) *Server {
	s.suppress = sup
	return s
}

// WithToken requires callers to present a token on every API route.
func (s *Server) WithToken(t *Token) *Server {
	s.token = t
	return s
}

// WithExecutor enables one-click remediation. Without it the dashboard shows
// alerts and playbook text only — which is a complete, useful product, so this
// stays optional rather than required.
func (s *Server) WithExecutor(e respond.Executor, quarantineDir string) *Server {
	s.exec = e
	s.quarantineDir = quarantineDir
	return s
}

// WithSettings enables the dashboard's configuration panel.
func (s *Server) WithSettings(st *settings.Store) *Server {
	s.settings = st
	return s
}

// SetStatus updates the telemetry status shown to the dashboard.
func (s *Server) SetStatus(st Status) {
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
}

// Addr is the loopback address the server binds.
func (s *Server) Addr() string { return s.addr }

type connectionDTO struct {
	Time       time.Time `json:"time"`
	LastSeen   time.Time `json:"lastSeen"`
	Events     int       `json:"events"`
	PID        uint32    `json:"pid"`
	Image      string    `json:"image"`
	RemoteIP   string    `json:"remoteIP"`
	RemotePort uint16    `json:"remotePort"`
	Proto      string    `json:"proto"`
	Domain     string    `json:"domain"`
	Verdict    string    `json:"verdict"`
	IPVersion  int       `json:"ipVersion"` // 4 or 6, for client-side filtering
	Inbound    bool      `json:"inbound"`
	ASN        uint32    `json:"asn"`
	ASOrg      string    `json:"asOrg"`
	Country    string    `json:"country"`
	ID         int64     `json:"id"`
	HasStory   bool      `json:"hasStory"`
}

type talkerDTO struct {
	Image string `json:"image"`
	Count int    `json:"count"`
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/connections", s.handleConnections)
	mux.HandleFunc("/api/talkers", s.handleTalkers)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleSettings(w, r) // reading configuration changes nothing
			return
		}
		guardMutation(s.handleSettings)(w, r)
	})
	mux.HandleFunc("/api/story", s.handleStory)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/ack", guardMutation(s.handleAckAlert))
	mux.HandleFunc("/api/alerts/allow", guardMutation(s.handleAllowAlert))
	mux.HandleFunc("/api/actions", s.handleActions)
	mux.HandleFunc("/api/actions/run", guardMutation(s.handleRunAction))
	mux.HandleFunc("/api/actions/undo", guardMutation(s.handleUndoAction))

	// Serve the embedded dashboard at "/". The embed root includes the
	// "dashboard" dir, so strip it to a clean file server.
	sub, err := fs.Sub(dashboardFS, "dashboard")
	if err == nil {
		mux.Handle("/", s.dashboardHandler(http.FileServer(http.FS(sub))))
	}

	// Token check wraps every /api route; the dashboard shell is served
	// separately above because it carries no data and must load to bootstrap.
	api := http.NewServeMux()
	api.Handle("/api/", s.requireToken(mux))
	api.Handle("/", mux)

	return requireLocalHost(api)
}

// requireLocalHost rejects requests whose Host header is not our loopback
// address.
//
// Binding 127.0.0.1 does not stop DNS rebinding: an attacker points
// evil.tld at 127.0.0.1 with a short TTL, and the browser then treats
// http://evil.tld:8973 as SAME-ORIGIN with the attacker's page — so CORS does
// not apply and the whole ledger (every process, destination and causal story)
// is readable. The Origin check on mutating routes does not help here, because
// same-origin GETs send no Origin header at all. Validating Host is the fix.
func requireLocalHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch host {
		case "127.0.0.1", "localhost", "::1", "[::1]":
			// Defence in depth for the one place attacker-influenced text is
			// injected as HTML, and against content sniffing.
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "requests must address this agent as 127.0.0.1", http.StatusForbidden)
		}
	})
}

// ListenAndServe binds the loopback address and serves until error.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.ledger.RecentConnections(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]connectionDTO, 0, len(rows))
	for _, c := range rows {
		out = append(out, connectionDTO{
			Time: c.Time, LastSeen: c.LastSeen, Events: c.Events,
			PID: c.PID, Image: c.Image, RemoteIP: c.RemoteIP,
			RemotePort: c.RemotePort, Proto: c.Proto, Domain: c.Domain, Verdict: c.Verdict,
			IPVersion: ipVersion(c.RemoteIP), Inbound: c.Inbound,
			ASN: c.ASN, ASOrg: c.ASOrg, Country: c.Country,
			ID: c.ID, HasStory: c.Story != "",
		})
	}
	writeJSON(w, out)
}

func (s *Server) handleTalkers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.ledger.RecentConnections(1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := map[string]int{}
	var order []string
	for _, c := range rows {
		if _, seen := counts[c.Image]; !seen {
			order = append(order, c.Image)
		}
		counts[c.Image]++
	}
	out := make([]talkerDTO, 0, len(order))
	for _, img := range order {
		out = append(out, talkerDTO{Image: img, Count: counts[img]})
	}
	writeJSON(w, out)
}

// ipVersion reports 4 or 6 for an address, or 0 if it isn't parseable.
func ipVersion(s string) int {
	ip := net.ParseIP(s)
	switch {
	case ip == nil:
		return 0
	case ip.To4() != nil:
		return 4
	default:
		return 6
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	st := s.status
	s.mu.RUnlock()
	writeJSON(w, st)
}

// handleSettings reads or updates the user-editable configuration.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		http.Error(w, "settings unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.settings.Get())
	case http.MethodPut, http.MethodPost:
		var v settings.Values
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&v); err != nil {
			http.Error(w, "invalid settings payload", http.StatusBadRequest)
			return
		}
		if err := s.settings.Set(v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, s.settings.Get()) // echo the sanitized result
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStory returns the stored causal chain for one connection: the answer to
// "why did this happen?", reconstructed from the GoRapide poset at record time.
func (s *Server) handleStory(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid id", http.StatusBadRequest)
		return
	}
	story, err := s.ledger.StoryFor(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if story == "" {
		http.Error(w, "no story recorded for this connection", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(story))
}

type alertDTO struct {
	ID        int64          `json:"id"`
	Time      time.Time      `json:"time"`
	RuleID    string         `json:"ruleId"`
	Area      string         `json:"area"`
	Severity  string         `json:"severity"`
	Title     string         `json:"title"`
	Narrative string         `json:"narrative"`
	Playbook  []string       `json:"playbook"`
	ConnID    int64          `json:"connId"`
	Evidence  map[string]any `json:"evidence"`
	Status    string         `json:"status"`
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.ledger.RecentAlerts(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]alertDTO, 0, len(rows))
	for _, a := range rows {
		pb := a.Playbook
		if pb == nil {
			pb = []string{}
		}
		out = append(out, alertDTO{
			ID: a.ID, Time: a.Time, RuleID: a.RuleID, Area: a.Area,
			Severity: a.Severity, Title: a.Title, Narrative: a.Narrative,
			Playbook: pb, ConnID: a.ConnID, Evidence: a.Evidence, Status: a.Status,
		})
	}
	writeJSON(w, out)
}

// guardMutation protects state-changing endpoints from cross-site requests.
//
// The API is unauthenticated because it binds loopback, which is the right call
// for a local dashboard — but "loopback" does not mean "only our page". Any web
// page the user visits can make its browser POST to 127.0.0.1, and these
// endpoints kill processes and move files. Two defences, both cheap:
//
//   - Require a custom header. Cross-origin JavaScript cannot set one without a
//     CORS preflight, and we answer no preflight, so the request never fires.
//   - Reject any request carrying a foreign Origin outright.
func guardMutation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && !isLocalOrigin(origin) {
			http.Error(w, "cross-site requests are not accepted", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-NiteWatch") == "" {
			http.Error(w, "missing X-NiteWatch header", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func isLocalOrigin(origin string) bool {
	return strings.HasPrefix(origin, "http://127.0.0.1:") ||
		strings.HasPrefix(origin, "http://localhost:")
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid id", http.StatusBadRequest)
		return
	}
	if err := s.ledger.AckAlert(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleAllowAlert records "stop telling me about this" for one specific
// rule + program + destination, and acknowledges the alert.
func (s *Server) handleAllowAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid id", http.StatusBadRequest)
		return
	}
	a, err := s.ledger.AlertByID(id)
	if err != nil {
		http.Error(w, "no such alert", http.StatusNotFound)
		return
	}

	image, _ := a.Evidence["ImagePath"].(string)
	dest, _ := a.Evidence["Destination"].(string)
	key := detect.Key(a.RuleID, image, dest)

	if err := s.ledger.AddAllow(key, a.Title, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.suppress != nil {
		s.suppress.AddKeys([]string{key})
	}
	_ = s.ledger.AckAlert(id)
	writeJSON(w, map[string]any{"ok": true, "allowed": key})
}

// handleActions lists the remediations available for an alert. Read-only:
// nothing here changes the machine.
func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("alert"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid alert id", http.StatusBadRequest)
		return
	}
	a, err := s.ledger.AlertByID(id)
	if err != nil {
		http.Error(w, "no such alert", http.StatusNotFound)
		return
	}
	acts := respond.Suggest(a.Area, a.Severity, a.Evidence)
	writeJSON(w, map[string]any{
		"available": s.exec != nil,
		"actions":   acts,
	})
}

// handleRunAction executes one remediation. POST only, and only ever in
// response to an explicit user click — there is no automatic path here.
func (s *Server) handleRunAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.exec == nil {
		http.Error(w, "remediation is not available on this system", http.StatusServiceUnavailable)
		return
	}
	alertID, err := strconv.ParseInt(r.URL.Query().Get("alert"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid alert id", http.StatusBadRequest)
		return
	}
	kind := respond.Kind(r.URL.Query().Get("kind"))

	a, err := s.ledger.AlertByID(alertID)
	if err != nil {
		http.Error(w, "no such alert", http.StatusNotFound)
		return
	}

	// Re-derive the action from the stored alert rather than trusting the
	// request body: a caller must not be able to name an arbitrary process to
	// kill or file to move by hand-crafting a request to the local API.
	var chosen *respond.Action
	for _, act := range respond.Suggest(a.Area, a.Severity, a.Evidence) {
		if act.Kind == kind {
			c := act
			chosen = &c
			break
		}
	}
	if chosen == nil {
		http.Error(w, "that action is not offered for this alert", http.StatusBadRequest)
		return
	}

	res := s.exec.Execute(*chosen)
	rec := ledger.ActionRecord{
		Time: time.Now(), AlertID: alertID, Kind: string(chosen.Kind),
		Label: chosen.Label, Params: chosen.Params,
		OK: res.OK, Message: res.Message, Undo: res.Undo,
	}
	recID, _ := s.ledger.RecordAction(rec)
	if res.OK {
		_ = s.ledger.AckAlert(alertID)
	}
	writeJSON(w, map[string]any{
		"ok": res.OK, "message": res.Message,
		"actionId": recID, "undoable": len(res.Undo) > 0,
	})
}

// handleUndoAction reverses a previously executed action.
func (s *Server) handleUndoAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.exec == nil {
		http.Error(w, "remediation is not available on this system", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "missing or invalid action id", http.StatusBadRequest)
		return
	}
	rec, err := s.ledger.ActionByID(id)
	if err != nil {
		http.Error(w, "no such action", http.StatusNotFound)
		return
	}
	if len(rec.Undo) == 0 {
		http.Error(w, "that action cannot be undone", http.StatusBadRequest)
		return
	}
	// Undo records come back from the database, which may be user-writable.
	// Validate structurally before acting on them with elevated privileges.
	if err := respond.ValidateUndo(respond.Kind(rec.Kind), rec.Undo, s.quarantineDir); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := s.exec.Undo(respond.Action{Kind: respond.Kind(rec.Kind), Params: rec.Params}, rec.Undo)
	if res.OK {
		_ = s.ledger.MarkUndone(id)
	}
	writeJSON(w, map[string]any{"ok": res.OK, "message": res.Message})
}

// dashboardHandler serves the shell with the API token injected, so the page
// can authenticate without the token ever appearing in a URL (where it would
// land in browser history and Referer headers).
func (s *Server) dashboardHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			next.ServeHTTP(w, r)
			return
		}
		page, err := dashboardFS.ReadFile("dashboard/index.html")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		body := strings.Replace(string(page), "__NITEWATCH_TOKEN__", s.token.Value(), 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
