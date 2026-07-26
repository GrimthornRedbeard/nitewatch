// Package detect evaluates rules against connections as they are recorded.
//
// Detectors are Go functions (matching needs ledger history, intel lookups, and
// causal-graph state that YAML cannot express); rules are data that bind a
// detector to a severity and the words shown to the user. A rule fires only if
// its detector matches AND the suppression gates pass.
package detect

import (
	"strings"

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

// detectRawIPNoDNS fires when an UNSIGNED program dials a bare address with no
// observed lookup.
//
// The unsigned requirement is not a refinement — it is what makes this rule
// viable at all. Live data from a normal desktop fired it on Steam contacting
// Valve, Blizzard's agent contacting Blizzard, Chrome and Claude contacting
// Anthropic, and Brave contacting a video-analytics host. Every one signed by
// its own vendor, every one legitimate. Five high-severity alerts in a minute
// for a machine doing nothing wrong.
//
// The cause is that "no lookup observed" stopped being a signal:
//
//   - DNS-over-HTTPS is the DEFAULT in Brave and Chrome and is spreading to the
//     OS. Those lookups are HTTPS to a resolver and produce no DNS telemetry
//     whatsoever, so every browser connection looks like a bare-address dial.
//   - Long-lived clients resolve once at launch and connect for hours after.
//   - Addresses arrive in config, in service discovery, and from previous runs.
//
// What remains genuinely odd is an unsigned binary — no publisher, nobody
// accountable — reaching a bare address on a network that is not shared
// hosting, for the first time. That combination is rare on a normal machine.
// Signed software doing it is simply how the modern web works, and saying
// otherwise trains people to dismiss the alerts that matter.
func detectRawIPNoDNS(s Subject, _ *Engine) map[string]any {
	if s.HadDNS || s.Conn.Inbound || !s.FirstContact {
		return nil
	}
	// A name from any source means the destination is identifiable, which is
	// the opposite of hiding.
	if s.Domain != "" {
		return nil
	}
	// Signed software is accountable to a publisher; that alone removes this
	// weak signal's entire basis.
	if s.Event.Signed {
		return nil
	}
	// Ownership data is what makes the rest judgeable, and it loads in the
	// background. Firing without it would reproduce the false positives on
	// every restart.
	if s.Recon.Org == "" || SharedInfrastructure(s.Recon.Org) {
		return nil
	}
	return map[string]any{}
}

// sharedInfraTokens identify networks that host everyone's traffic. Substring
// matching is correct here, unlike for publisher trust: this list only
// SUPPRESSES a weak signal, so a false match costs sensitivity rather than
// granting trust, and AS names carry inconsistent suffixes
// ("CLOUDFLARENET", "AMAZON-02", "GOOGLE-CLOUD-PLATFORM").
var sharedInfraTokens = []string{
	"cloudflare", "fastly", "akamai", "amazon", "aws", "google", "microsoft",
	"azure", "digitalocean", "linode", "hetzner", "ovh", "cloudfront",
	"edgecast", "stackpath", "bunny", "vercel", "netlify", "oracle", "alibaba",
	"apple", "facebook", "meta", "cdn77", "limelight", "incapsula", "sucuri",
	"github", "gitlab", "leaseweb", "godaddy", "automattic",
}

// SharedInfrastructure reports whether an AS owner is a CDN or cloud provider.
func SharedInfrastructure(org string) bool {
	if org == "" {
		return false
	}
	o := strings.ToLower(org)
	for _, t := range sharedInfraTokens {
		if strings.Contains(o, t) {
			return true
		}
	}
	return false
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
