// Package api exposes the ledger over a loopback-only HTTP+JSON interface for
// the local dashboard. Binding is 127.0.0.1 exclusively — a hard privacy
// constraint, never 0.0.0.0.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/threattape/nitewatch/agent/internal/buildinfo"
	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/explain"
	"github.com/threattape/nitewatch/agent/internal/help"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/legal"
	"github.com/threattape/nitewatch/agent/internal/platform"
	"github.com/threattape/nitewatch/agent/internal/rdap"
	"github.com/threattape/nitewatch/agent/internal/respond"
	"github.com/threattape/nitewatch/agent/internal/selftest"
	"github.com/threattape/nitewatch/agent/internal/settings"
	"github.com/threattape/nitewatch/agent/internal/tip"
	"github.com/threattape/nitewatch/agent/internal/vt"
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
	rdap          *rdap.Client
	vt            *vt.Client
	stop          func()
	engine        *detect.Engine
	feeds         *intel.Store
	addr          string
	build         buildinfo.Info

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

// WithLookups enables the on-demand registration lookup.
//
// Kept optional and off by default because it is the one feature that sends
// anything about the user's machine off the box. Wiring it in is a deliberate
// act; firing it is a second deliberate act, by the user, per address.
func (s *Server) WithLookups(c *rdap.Client) *Server {
	s.rdap = c
	return s
}

// WithShutdown lets the dashboard stop the agent, which is what "I do not
// accept these terms" has to mean to be worth anything.
func (s *Server) WithShutdown(stop func()) *Server {
	s.stop = stop
	return s
}

// WithSettings enables the dashboard's configuration panel.
// WithBuild records which build is running, for display in the About panel.
func (s *Server) WithBuild(b buildinfo.Info) *Server {
	s.build = b
	return s
}

func (s *Server) WithSettings(st *settings.Store) *Server {
	s.settings = st
	s.vt = vt.New(st.Get().VirusTotalKey)
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
	BytesSent  uint64    `json:"bytesSent"`
	BytesRecv  uint64    `json:"bytesRecv"`
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
	mux.HandleFunc("/api/process", s.handleProcess)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/ack", guardMutation(s.handleAckAlert))
	mux.HandleFunc("/api/alerts/allow", guardMutation(s.handleAllowAlert))
	mux.HandleFunc("/api/actions", s.handleActions)
	mux.HandleFunc("/api/actions/run", guardMutation(s.handleRunAction))
	mux.HandleFunc("/api/actions/undo", guardMutation(s.handleUndoAction))
	// POST, and guarded like a mutation, because it is one: it causes an
	// outbound request that tells a registry what the user is looking at.
	// Nothing should be able to trigger it by embedding a URL.
	mux.HandleFunc("/api/lookup", guardMutation(s.handleLookup))
	mux.HandleFunc("/api/explain", s.handleExplain)
	mux.HandleFunc("/api/terms", s.handleTerms)
	mux.HandleFunc("/api/help", s.handleHelp)
	mux.HandleFunc("/api/terms/accept", guardMutation(s.handleAcceptTerms))
	mux.HandleFunc("/api/tip", s.handleTip)
	mux.HandleFunc("/api/tip/dismiss", guardMutation(s.handleDismissTip))
	mux.HandleFunc("/api/shutdown", guardMutation(s.handleShutdown))
	// Both mutate: one writes alerts, the other deletes them. Guarded so no
	// link or image can make the agent shout at somebody.
	mux.HandleFunc("/api/selftest", guardMutation(s.handleSelfTest))
	mux.HandleFunc("/api/selftest/plan", s.handleSelfTestPlan)
	// Hashing a large file costs real time and touches the disk, so it happens
	// only when the user asks. Guarded like a mutation for that reason.
	mux.HandleFunc("/api/verify", guardMutation(s.handleVerify))
	mux.HandleFunc("/api/reputation", guardMutation(s.handleReputation))
	mux.HandleFunc("/api/selftest/clear", guardMutation(s.handleClearDrills))

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
			BytesSent: c.BytesSent, BytesRecv: c.BytesRecv,
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
		writeJSON(w, redactSecrets(s.settings.Get()))
	case http.MethodPut, http.MethodPost:
		var v settings.Values
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&v); err != nil {
			http.Error(w, "invalid settings payload", http.StatusBadRequest)
			return
		}
		// An empty key on save means "leave it alone", not "delete it" — the GET
		// above never hands the real one back, so a round-trip through the
		// settings form would otherwise wipe it. Clearing is explicit.
		if v.VirusTotalKey == "" && r.URL.Query().Get("clearKey") == "" {
			v.VirusTotalKey = s.settings.Get().VirusTotalKey
		}
		if err := s.settings.Set(v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.refreshVT()
		writeJSON(w, redactSecrets(s.settings.Get()))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// redactSecrets strips credentials before settings go over the wire. The API is
// token-guarded, so this is defence in depth rather than the boundary — but a
// key that is never echoed cannot leak through a screenshot, a bug report, or a
// browser extension reading the page.
func redactSecrets(v settings.Values) map[string]any {
	return map[string]any{
		"includeLocal":  v.IncludeLocal,
		"resolveNames":  v.ResolveNames,
		"recon":         v.Recon,
		"dedupSeconds":  v.DedupSeconds,
		"retentionDays": v.RetentionDays,
		// Whether a key is set, never the key itself.
		"virusTotalKeySet": v.VirusTotalKey != "",
	}
}

// refreshVT rebuilds the reputation client after the key changes.
func (s *Server) refreshVT() {
	if s.settings == nil {
		return
	}
	s.mu.Lock()
	s.vt = vt.New(s.settings.Get().VirusTotalKey)
	s.mu.Unlock()
}

// handleReputation asks VirusTotal about one file's fingerprint.
//
// The single most sensitive thing this agent can do, and gated accordingly:
// POST only, guarded, disabled unless the user supplied their own key, and
// never called by anything automatic. The UI states what leaves the machine and
// what it does not before the button is pressed.
func (s *Server) handleReputation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	client := s.vt
	s.mu.RUnlock()
	if client == nil || !client.Enabled() {
		http.Error(w, "no VirusTotal key is configured — add one in Settings to switch this on",
			http.StatusNotFound)
		return
	}
	sum := r.URL.Query().Get("sha256")
	if sum == "" {
		http.Error(w, "missing sha256", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	rep, err := client.Lookup(ctx, sum)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, rep)
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

// handleLookup asks a public registry who a destination belongs to.
//
// This is the only route in the agent that reaches the internet on behalf of a
// user action, so the rules around it are strict: POST only, so it cannot be
// triggered by a link or an image; guarded like a mutation; and never called by
// anything the dashboard does on its own. The button that reaches it says what
// it will do before it does it.
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.rdap == nil {
		http.Error(w, "registration lookups are not enabled on this agent", http.StatusNotFound)
		return
	}
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Error(w, "missing q", http.StatusBadRequest)
		return
	}
	// The address is passed alongside the name so the client can answer the
	// question the user meant: registries hold no record for most hostnames,
	// and many hostnames are generated from the address anyway.
	ip := r.URL.Query().Get("ip")

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	reg, err := s.rdap.LookupBest(ctx, q, ip)
	if err != nil {
		// The message is written for a person to read, so pass it through rather
		// than flattening it to a status code.
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, reg)
}

// handleExplain serves the plain-English layer: what a program is, and what the
// jargon on screen means. Answered entirely from a table compiled into the
// binary — no lookup leaves the machine, and nothing here influences detection.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if image := r.URL.Query().Get("image"); image != "" {
		p, ok := explain.ForImage(image)
		if !ok {
			// Silence is the correct answer for something we do not recognise.
			// Guessing would be a confident lie to somebody with no way to check.
			writeJSON(w, map[string]any{"known": false})
			return
		}
		writeJSON(w, map[string]any{"known": true, "program": p})
		return
	}
	writeJSON(w, map[string]any{"terms": explain.AllTerms()})
}

// WithSelfTest enables the on-demand drill. Optional, like the executor: an
// agent without it still alerts normally.
func (s *Server) WithSelfTest(e *detect.Engine, feeds *intel.Store) *Server {
	s.engine = e
	s.feeds = feeds
	return s
}

// handleSelfTestPlan describes what the drill will do, before it does it. Read
// only — the UI shows this so nobody presses a button whose effect is a screen
// full of "your files are being encrypted" they did not expect.
func (s *Server) handleSelfTestPlan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"scenarios": selftest.Explain(time.Now())})
}

func (s *Server) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.engine == nil {
		http.Error(w, "detection is not enabled on this agent, so there is nothing to test", http.StatusNotFound)
		return
	}
	res, err := selftest.Run(s.engine, s.feeds, s.ledger, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleClearDrills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n, err := s.ledger.DeleteDrillAlerts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"removed": n})
}

// handleVerify gathers everything the machine itself can say about a program
// file: its hash, its size, and the publisher details embedded in it.
//
// Nothing is sent anywhere. The point is to hand the user facts they can check
// themselves — pasting a hash into a reputation service is their decision to
// make, on a machine of their choosing, not something this agent does on their
// behalf.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	image := r.URL.Query().Get("image")
	if image == "" {
		http.Error(w, "missing image", http.StatusBadRequest)
		return
	}
	id := platform.Identify(image)
	signed, signer := platform.FileSigner(image)
	trust := detect.ClassifyInstall(image, signed, signer)
	pkg, ver, pubID, isStore := detect.StorePackage(image)

	writeJSON(w, map[string]any{
		"identity": id,
		"signed":   signed,
		"signer":   signer,
		"vouched":  trust.Vouched,
		"why":      trust.Why,
		"store":    isStore,
		"package":  map[string]any{"name": pkg, "version": ver, "publisherId": pubID},
	})
}

// handleHelp serves the known-limitations document, compiled into the binary.
//
// The disclaimer tells people to read it, and somebody running the exe has no
// repository to read it in — so it travels with the build or the instruction is
// worthless.
func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	// The build identity rides along with the documents because they share a
	// panel, and because "which version are you running?" is the first question
	// asked of any bug report from a public download.
	writeJSON(w, map[string]any{
		"docs":  help.Docs(),
		"build": s.build,
		"label": s.build.Label(),
	})
}

// handleTerms serves the pre-release disclaimer and whether it has been
// accepted. Readable without accepting, obviously — refusing to show somebody
// the terms until they agree to them would be quite the trick.
func (s *Server) handleTerms(w http.ResponseWriter, r *http.Request) {
	accepted := false
	if s.settings != nil {
		accepted = s.settings.Get().AcceptedTerms == legal.Version()
	}
	writeJSON(w, map[string]any{
		"headline": legal.Headline,
		"plain":    legal.Plain,
		"formal":   legal.Formal,
		"version":  legal.Version(),
		"accepted": accepted,
	})
}

func (s *Server) handleAcceptTerms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.settings == nil {
		http.Error(w, "settings unavailable, so acceptance cannot be recorded",
			http.StatusServiceUnavailable)
		return
	}
	v := s.settings.Get()
	v.AcceptedTerms = legal.Version()
	if err := s.settings.Set(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("terms: accepted (version %s)", legal.Version())
	writeJSON(w, map[string]any{"accepted": true, "version": legal.Version()})
}

// tipInterval is how long a dismissal lasts.
//
// Slightly under a day, so the notice does not settle into a fixed hour that a
// user with a routine never happens to be at the machine for. Long enough that
// nobody meets it twice in a working day.
const tipInterval = 20 * time.Hour

// handleTip serves the contribution notice and whether now is a moment to show
// it. The decision is made here rather than in the page so that a reload cannot
// re-trigger it, and so the pacing survives somebody clearing browser storage.
func (s *Server) handleTip(w http.ResponseWriter, r *http.Request) {
	show := false
	if s.settings != nil {
		v := s.settings.Get()
		// Never over the disclaimer. Being asked for money before being told
		// the software is unfinished and unwarranted has the order of those two
		// conversations exactly backwards.
		accepted := v.AcceptedTerms == legal.Version()
		due := time.Since(time.Unix(v.TipSnoozedUnix, 0)) >= tipInterval
		show = accepted && !v.Contributor && due
	}
	writeJSON(w, map[string]any{
		"headline": tip.Headline,
		"body":     tip.Body,
		"thanks":   tip.Dismissed,
		"payPal":   tip.PayPal,
		"contact":  tip.Contact,
		"show":     show,
		"monthly":  tip.MonthlyThreshold,
		"credits":  tip.CreditsThreshold,
	})
}

// handleDismissTip records either "not now" or "I contribute".
//
// The contributor claim is stored exactly as given. There is no verification
// step and there is not going to be one; see internal/tip for why.
func (s *Server) handleDismissTip(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		http.Error(w, "settings unavailable, so this cannot be recorded",
			http.StatusServiceUnavailable)
		return
	}
	v := s.settings.Get()
	v.TipSnoozedUnix = time.Now().Unix()
	if r.URL.Query().Get("contributor") == "1" {
		v.Contributor = true
	}
	if err := s.settings.Set(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"contributor": v.Contributor})
}

// handleShutdown stops the agent, for somebody who read the terms and decided
// no. Declining and then leaving the thing running would make the choice
// meaningless.
//
// This adds no capability an attacker does not already have: anything holding
// the API token runs as the same user and can simply kill the process.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Print("shutdown: requested from the dashboard")
	writeJSON(w, map[string]any{"stopping": true})
	go func() {
		// Let the response reach the browser before the process goes away.
		time.Sleep(400 * time.Millisecond)
		if s.stop != nil {
			s.stop()
			return
		}
		os.Exit(0)
	}()
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
		// Never cache this page. Two reasons, and the second is the serious one:
		//
		//   - It is served from an embedded filesystem whose modification time
		//     is zero, so net/http emits no Last-Modified and no ETag. With no
		//     validators and no freshness directives, a browser is free to keep
		//     serving whatever it has — which is how somebody upgrades the agent
		//     and still sees the previous version's interface.
		//   - The page carries this run's API token, substituted above. A cached
		//     copy holds a token from an earlier run, which is both a stale
		//     credential sitting in the browser cache and a page that will fail
		//     to authenticate after a restart.
		//
		// It is a small file served over loopback. There is nothing to gain by
		// caching it and two distinct ways for it to go wrong.
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		_, _ = w.Write([]byte(body))
	})
}

// handleProcess assembles everything known about one program.
//
// The causal data was previously scattered: a chain behind a row click, a
// context panel that only appeared when something had already gone wrong. This
// is the place a person can actually go and ask "what is this program doing?"
// — its identity, what started it, everywhere it talks, how much it sends, and
// anything ever raised about it.
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	if image == "" {
		http.Error(w, "missing image", http.StatusBadRequest)
		return
	}

	conns, err := s.ledger.ConnectionsForImage(image, 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	alerts, _ := s.ledger.AlertsForImage(image, 20)

	var sent, recv uint64
	dests := map[string]bool{}
	countries := map[string]bool{}
	var latestPID uint32
	var story string
	out := make([]connectionDTO, 0, len(conns))
	for i, c := range conns {
		sent += c.BytesSent
		recv += c.BytesRecv
		d := c.Domain
		if d == "" {
			d = c.RemoteIP
		}
		dests[d] = true
		if c.Country != "" {
			countries[c.Country] = true
		}
		if i == 0 {
			latestPID = c.PID
			story = c.Story // the most recent causal chain for this program
		}
		out = append(out, connectionDTO{
			Time: c.Time, LastSeen: c.LastSeen, Events: c.Events, PID: c.PID,
			Image: c.Image, RemoteIP: c.RemoteIP, RemotePort: c.RemotePort,
			Proto: c.Proto, Domain: c.Domain, Verdict: c.Verdict,
			IPVersion: ipVersion(c.RemoteIP), Inbound: c.Inbound,
			ASN: c.ASN, ASOrg: c.ASOrg, Country: c.Country,
			ID: c.ID, HasStory: c.Story != "",
			BytesSent: c.BytesSent, BytesRecv: c.BytesRecv,
		})
	}

	alertOut := make([]alertDTO, 0, len(alerts))
	for _, a := range alerts {
		pb := a.Playbook
		if pb == nil {
			pb = []string{}
		}
		alertOut = append(alertOut, alertDTO{
			ID: a.ID, Time: a.Time, RuleID: a.RuleID, Area: a.Area,
			Severity: a.Severity, Title: a.Title, Narrative: a.Narrative,
			Playbook: pb, ConnID: a.ConnID, Evidence: a.Evidence, Status: a.Status,
		})
	}

	writeJSON(w, map[string]any{
		"image":        image,
		"pid":          latestPID,
		"connections":  out,
		"alerts":       alertOut,
		"bytesSent":    sent,
		"bytesRecv":    recv,
		"destinations": len(dests),
		"countries":    len(countries),
		"story":        json.RawMessage(storyOrNull(story)),
	})
}

func storyOrNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
