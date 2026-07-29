// Package vt asks VirusTotal what antivirus engines make of a specific file.
//
// PRIVACY — read this before changing anything here.
//
// This sends a SHA-256 hash to a third party. That is a smaller disclosure than
// uploading the file, and a much smaller one than it might appear: a hash
// carries no filename, no path, no username and nothing about the rest of the
// machine. VirusTotal answers from a database it already has; it learns only
// that somebody asked about one particular file.
//
// But it is not nothing, and the honest account has three parts:
//
//  1. For a widely-distributed file (chrome.exe, a Windows component) the query
//     is indistinguishable from the thousands of others VirusTotal sees for it.
//     It reveals essentially nothing.
//  2. For a RARE file — something built in-house, a niche tool, a one-off build
//     — the hash is close to an identifier. Asking about it says "somebody
//     possesses this exact file."
//  3. VirusTotal's paid tiers let customers see who is looking up hashes they
//     care about. In a targeted intrusion, querying the attacker's implant can
//     tell the attacker you found it. This matters to almost nobody, and to a
//     handful of people it matters enormously.
//
// So: never automatic, never on ingest, never on a timer. It runs when a person
// presses a button about one file they are already suspicious of, having been
// shown the above. Results are cached so a second look does not repeat the
// disclosure. The feature is off until the user supplies their own API key,
// which means the account doing the asking is theirs, not ours.
package vt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// Report is what VirusTotal says about one file, reduced to what a person can
// act on.
type Report struct {
	SHA256 string `json:"sha256"`
	// Known reports whether VirusTotal has ever seen this file. A file it has
	// never seen is not thereby bad — but for something claiming to be
	// well-known software it is a strange thing to be.
	Known bool `json:"known"`

	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
	Total      int `json:"total"`

	// Names VirusTotal has seen this file distributed under. Useful precisely
	// when they disagree with the name on this machine.
	Names []string `json:"names,omitempty"`
	// Labels are the threat names engines assigned, when any did.
	Labels []string `json:"labels,omitempty"`

	FirstSeen  string `json:"firstSeen,omitempty"`
	LastSeen   string `json:"lastSeen,omitempty"`
	Reputation int    `json:"reputation"`

	// Verdict and Advice are the plain-English reading of the numbers above.
	// Rendering them here rather than in the UI keeps the interpretation in one
	// place and under test — this is exactly the sort of number that misleads
	// when presented raw.
	Verdict string `json:"verdict"`
	Advice  string `json:"advice"`
}

type Client struct {
	mu     sync.Mutex
	cache  map[string]cached
	http   *http.Client
	apiKey string
	// BaseURL is overridable for tests.
	BaseURL string
}

type cached struct {
	rep Report
	at  time.Time
}

// CacheTTL: an antivirus verdict on a fixed file changes over days, not
// minutes. An hour keeps repeat presses off the network entirely.
const CacheTTL = time.Hour

func New(apiKey string) *Client {
	return &Client{
		cache:   map[string]cached{},
		http:    &http.Client{Timeout: 20 * time.Second},
		apiKey:  apiKey,
		BaseURL: "https://www.virustotal.com/api/v3",
	}
}

// Enabled reports whether a key has been configured. Without one the feature
// does not exist rather than failing at the moment of use.
func (c *Client) Enabled() bool { return c != nil && c.apiKey != "" }

var sha256Re = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// Lookup asks about one hash. The caller is responsible for a person having
// asked.
func (c *Client) Lookup(ctx context.Context, sha256 string) (Report, error) {
	if !c.Enabled() {
		return Report{}, fmt.Errorf("no VirusTotal key is configured, so this check is switched off")
	}
	// The hash goes into a URL path. Only a literal SHA-256 may pass — this is
	// the same reasoning as the RDAP client: arriving from our own dashboard is
	// not a reason to trust a string.
	if !sha256Re.MatchString(sha256) {
		return Report{}, fmt.Errorf("that is not a SHA-256 fingerprint")
	}

	c.mu.Lock()
	if hit, ok := c.cache[sha256]; ok && time.Since(hit.at) < CacheTTL {
		c.mu.Unlock()
		return hit.rep, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/files/"+sha256, nil)
	if err != nil {
		return Report{}, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Report{}, fmt.Errorf("could not reach VirusTotal: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// Never seen. That is an answer, not an error, and an interesting one.
		rep := Report{SHA256: sha256, Known: false,
			Verdict: "VirusTotal has never seen this file.",
			Advice: "That is not the same as bad. Files built on your own machine, " +
				"niche tools and very new releases are all unknown. But software that " +
				"claims to be well known should not be — if this says it is from a big " +
				"company and nobody has ever seen it, those two facts disagree."}
		c.store(sha256, rep)
		return rep, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return Report{}, fmt.Errorf("VirusTotal rejected the API key")
	case http.StatusTooManyRequests:
		return Report{}, fmt.Errorf("VirusTotal's free allowance is used up for now — it permits about four checks a minute")
	default:
		return Report{}, fmt.Errorf("VirusTotal returned %s", resp.Status)
	}

	var raw vtResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&raw); err != nil {
		return Report{}, fmt.Errorf("could not read VirusTotal's answer: %w", err)
	}
	rep := raw.normalise(sha256)
	c.store(sha256, rep)
	return rep, nil
}

func (c *Client) store(k string, r Report) {
	c.mu.Lock()
	c.cache[k] = cached{rep: r, at: time.Now()}
	c.mu.Unlock()
}

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]struct {
				Category string `json:"category"`
				Result   string `json:"result"`
			} `json:"last_analysis_results"`
			Names            []string `json:"names"`
			Reputation       int      `json:"reputation"`
			FirstSubmission  int64    `json:"first_submission_date"`
			LastAnalysisDate int64    `json:"last_analysis_date"`
		} `json:"attributes"`
	} `json:"data"`
}

func (v vtResponse) normalise(sha string) Report {
	a := v.Data.Attributes
	st := a.LastAnalysisStats
	r := Report{
		SHA256: sha, Known: true,
		Malicious: st.Malicious, Suspicious: st.Suspicious,
		Harmless: st.Harmless, Undetected: st.Undetected,
		Total:      st.Malicious + st.Suspicious + st.Harmless + st.Undetected + st.Timeout,
		Reputation: a.Reputation,
	}
	if a.FirstSubmission > 0 {
		r.FirstSeen = time.Unix(a.FirstSubmission, 0).UTC().Format("2006-01-02")
	}
	if a.LastAnalysisDate > 0 {
		r.LastSeen = time.Unix(a.LastAnalysisDate, 0).UTC().Format("2006-01-02")
	}
	for i, n := range a.Names {
		if i >= 5 {
			break
		}
		r.Names = append(r.Names, n)
	}
	seen := map[string]bool{}
	for _, res := range a.LastAnalysisResults {
		if (res.Category == "malicious" || res.Category == "suspicious") && res.Result != "" && !seen[res.Result] {
			seen[res.Result] = true
			r.Labels = append(r.Labels, res.Result)
			if len(r.Labels) >= 6 {
				break
			}
		}
	}
	r.Verdict, r.Advice = interpret(r)
	return r
}

// interpret turns the counts into something a person can act on.
//
// This is the part that matters. A raw "3/72" misleads in both directions:
// people read any red as infection, and read zero as proof of safety. Neither
// is true. Heuristic engines produce false positives on installers, packers and
// small utilities constantly; and brand-new malware is detected by nobody on
// its first day, which is precisely when it is being used.
func interpret(r Report) (verdict, advice string) {
	switch {
	case r.Malicious >= 10:
		return fmt.Sprintf("%d of %d antivirus engines call this malicious.", r.Malicious, r.Total),
			"That level of agreement is not a false alarm. Treat this program as hostile: " +
				"stop it, and run a full Microsoft Defender scan. If it had access to your " +
				"passwords, change them from a different device."
	case r.Malicious >= 3:
		return fmt.Sprintf("%d of %d antivirus engines call this malicious.", r.Malicious, r.Total),
			"Several engines agreeing is worth taking seriously, though not yet conclusive. " +
				"If you did not deliberately install this, stop it and run a full scan."
	case r.Malicious >= 1 || r.Suspicious >= 1:
		return fmt.Sprintf("%d of %d engines flagged this; the rest did not.",
				r.Malicious+r.Suspicious, r.Total),
			"One or two engines disagreeing with everybody else is usually a false alarm — " +
				"installers, compression tools and small utilities trip heuristics all the " +
				"time. Weigh it against whether you recognise the program and where it lives."
	default:
		return fmt.Sprintf("None of the %d antivirus engines flagged this.", r.Total),
			"Reassuring, but not a guarantee. Brand-new malware is detected by nobody on its " +
				"first day, which is exactly when it gets used. Treat this as one piece of " +
				"evidence alongside where the program lives and whether you installed it."
	}
}
