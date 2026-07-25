// Package api exposes the ledger over a loopback-only HTTP+JSON interface for
// the local dashboard. Binding is 127.0.0.1 exclusively — a hard privacy
// constraint, never 0.0.0.0.
package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/threattape/nitewatch/agent/internal/ledger"
)

// DefaultAddr is the loopback address the dashboard/API listens on.
const DefaultAddr = "127.0.0.1:8973"

type Server struct {
	ledger *ledger.DB
	addr   string
}

func New(led *ledger.DB) *Server {
	return &Server{ledger: led, addr: DefaultAddr}
}

// Addr is the loopback address the server binds.
func (s *Server) Addr() string { return s.addr }

type connectionDTO struct {
	Time       time.Time `json:"time"`
	PID        uint32    `json:"pid"`
	Image      string    `json:"image"`
	RemoteIP   string    `json:"remoteIP"`
	RemotePort uint16    `json:"remotePort"`
	Proto      string    `json:"proto"`
	Domain     string    `json:"domain"`
	Verdict    string    `json:"verdict"`
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
			Time: c.Time, PID: c.PID, Image: c.Image, RemoteIP: c.RemoteIP,
			RemotePort: c.RemotePort, Proto: c.Proto, Domain: c.Domain, Verdict: c.Verdict,
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
