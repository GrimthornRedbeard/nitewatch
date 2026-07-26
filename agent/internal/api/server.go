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
	"sync"
	"time"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/settings"
)

//go:embed dashboard
var dashboardFS embed.FS

// DefaultAddr is the loopback address the dashboard/API listens on.
const DefaultAddr = "127.0.0.1:8973"

type Server struct {
	ledger   *ledger.DB
	settings *settings.Store
	addr     string

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
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/story", s.handleStory)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/ack", s.handleAckAlert)

	// Serve the embedded dashboard at "/". The embed root includes the
	// "dashboard" dir, so strip it to a clean file server.
	sub, err := fs.Sub(dashboardFS, "dashboard")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}
	return mux
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
