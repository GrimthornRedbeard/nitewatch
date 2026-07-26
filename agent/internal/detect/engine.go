// Package detect evaluates rules against connections as they are recorded.
//
// Detectors are Go functions (matching needs ledger history, intel lookups, and
// causal-graph state that YAML cannot express); rules are data that bind a
// detector to a severity and the words shown to the user. A rule fires only if
// its detector matches AND the suppression gates pass.
package detect

import (
	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

// Subject is everything known about one connection at detection time.
type Subject struct {
	Event  event.NormalizedEvent
	Conn   ledger.Connection
	Recon  recon.Info
	Domain string // the observed or resolved name, "" if none

	// HadDNS reports whether a DNS lookup by this process produced this
	// address. Distinct from Domain != "": a reverse-DNS name proves nothing
	// about whether the program looked the address up.
	HadDNS bool
	// FirstContact is true when this process has never reached this
	// destination before.
	FirstContact bool
}

// Detection is a rule that matched, with the data its templates need.
type Detection struct {
	Rule   *rules.Rule
	Fields map[string]any
}

// Detector decides whether a subject matches. It returns the template fields to
// merge on a match, or nil for no match.
type Detector func(s Subject, e *Engine) map[string]any

// Engine evaluates the loaded rule set against subjects.
type Engine struct {
	set   *rules.Set
	intel *intel.Store
	dets  map[string]Detector
}

// New builds an engine. A nil intel store simply disables feed-based detectors.
func New(set *rules.Set, feeds *intel.Store) *Engine {
	e := &Engine{set: set, intel: feeds}
	e.dets = map[string]Detector{
		"connection-intel-hit":  detectIntelHit,
		"raw-ip-no-dns":         detectRawIPNoDNS,
		"unsigned-outbound":     detectUnsignedOutbound,
		"foreign-first-contact": detectForeignFirstContact,
	}
	return e
}

// Evaluate runs every detector that has rules bound to it and returns the
// detections that matched.
func (e *Engine) Evaluate(s Subject) []Detection {
	var out []Detection
	for name, det := range e.dets {
		bound := e.set.For(name)
		if len(bound) == 0 {
			continue // no rule cares about this detector; skip the work
		}
		fields := det(s, e)
		if fields == nil {
			continue
		}
		base := baseFields(s)
		for k, v := range fields {
			base[k] = v
		}
		// Rules are severity-sorted; the most serious one for a detector wins,
		// so one condition cannot produce a pile of duplicate alerts.
		out = append(out, Detection{Rule: bound[0], Fields: base})
	}
	return out
}

// baseFields are available to every rule template.
func baseFields(s Subject) map[string]any {
	dest := s.Domain
	if dest == "" {
		dest = s.Conn.RemoteIP
	}
	return map[string]any{
		"ProcessName": shortName(s.Conn.Image),
		"ImagePath":   s.Conn.Image,
		"PID":         s.Conn.PID,
		"Destination": dest,
		"RemoteIP":    s.Conn.RemoteIP,
		"RemotePort":  s.Conn.RemotePort,
		"Domain":      s.Domain,
		"Owner":       s.Recon.Org,
		"Country":     s.Recon.Country,
		"ASN":         s.Recon.ASN,
	}
}

func shortName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	if p == "" {
		return "An unknown program"
	}
	return p
}

// --- detectors ---

// detectIntelHit fires when the destination is on a malicious feed. Context
// feeds (Tor) never fire alone — see the package docs in internal/intel.
func detectIntelHit(s Subject, e *Engine) map[string]any {
	if e.intel == nil {
		return nil
	}
	if m, ok := e.intel.FlagIP(s.Conn.RemoteIP); ok && m.Confidence == intel.Malicious {
		return map[string]any{"FeedName": m.Feed, "FeedReason": m.Reason}
	}
	if s.Domain != "" {
		if m, ok := e.intel.FlagDomain(s.Domain); ok && m.Confidence == intel.Malicious {
			return map[string]any{"FeedName": m.Feed, "FeedReason": m.Reason}
		}
	}
	return nil
}

// detectRawIPNoDNS fires when a program dials a bare address it never looked
// up. Normal software resolves names; malware often carries hardcoded addresses
// precisely to avoid leaving DNS evidence.
func detectRawIPNoDNS(s Subject, _ *Engine) map[string]any {
	if s.HadDNS || s.Conn.Inbound {
		return nil
	}
	// Only meaningful for a destination we have never seen this process use —
	// otherwise every long-lived connection re-fires.
	if !s.FirstContact {
		return nil
	}
	return map[string]any{}
}

// detectUnsignedOutbound fires when an unsigned program makes its first
// contact with a destination. Signature data is Windows-only; elsewhere Signed
// is false for everything, so the FirstContact gate keeps this quiet.
func detectUnsignedOutbound(s Subject, _ *Engine) map[string]any {
	if s.Event.Signed || s.Conn.Inbound || !s.FirstContact {
		return nil
	}
	if s.Event.Kind != event.KindNetConnect || s.Conn.Image == "" {
		return nil
	}
	return map[string]any{}
}

// detectForeignFirstContact fires on first contact with a network registered in
// a country the user's software has no other business in. Deliberately Medium
// severity in the pack: geography is a hint, not a verdict — plenty of
// legitimate services are hosted abroad.
func detectForeignFirstContact(s Subject, _ *Engine) map[string]any {
	if !s.FirstContact || s.Conn.Inbound || s.Recon.Country == "" {
		return nil
	}
	if !watchedCountry(s.Recon.Country) {
		return nil
	}
	return map[string]any{}
}

// watchedCountries are jurisdictions that warrant a look on first contact for a
// consumer endpoint. This is NOT a claim that traffic there is malicious; it is
// a prompt to check, and the rule that uses it says so plainly.
var watchedCountries = map[string]bool{
	"RU": true, "KP": true, "IR": true, "BY": true, "SY": true,
}

func watchedCountry(cc string) bool { return watchedCountries[cc] }
