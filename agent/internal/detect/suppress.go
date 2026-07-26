package detect

import (
	"strings"
	"sync"
	"time"
)

// Suppressor decides whether a detection should reach the user.
//
// This is the make-or-break layer. A security tool that cries wolf gets
// dismissed, and a dismissed tool protects nobody — so a false positive is not
// a cosmetic problem, it is a failure of the product's core function. Every
// gate here exists because some category of ordinary behaviour would otherwise
// generate alerts forever.
type Suppressor struct {
	mu sync.RWMutex
	// allow holds user decisions: "stop telling me about this".
	allow map[string]bool
	// firstSeen records when each program was first observed, so freshly
	// installed software can be treated more gently than a long-quiet binary
	// that suddenly starts talking.
	firstSeen map[string]time.Time
	// learningWindow is how long after first sighting a program's behaviour is
	// treated as installation activity rather than anomaly.
	learningWindow time.Duration
}

// DefaultLearningWindow: software does its noisiest, most unusual work in the
// first minutes after installation — registering autostarts, contacting update
// and telemetry endpoints it will never use again. Alerting on all of that
// teaches users that installing anything produces warnings.
const DefaultLearningWindow = 10 * time.Minute

func NewSuppressor() *Suppressor {
	return &Suppressor{
		allow:          map[string]bool{},
		firstSeen:      map[string]time.Time{},
		learningWindow: DefaultLearningWindow,
	}
}

// trustedSigners are publisher common names whose VERIFIED signature makes
// low-severity behavioural noise uninteresting.
//
// Matched EXACTLY, not by substring. Substring matching was a real hole: a
// certificate legitimately issued to "Intelligent Systems Ltd" contains
// "intel", "Googleplex Media" contains "google", and anyone can buy a code
// signing certificate for a company they actually registered. Suppression is a
// trust decision, so it may not be reachable by choosing a company name.
var trustedSigners = map[string]bool{
	"microsoft corporation":                              true,
	"microsoft windows":                                  true,
	"microsoft windows hardware compatibility publisher": true,
	"google llc":                                         true,
	"google inc":                                         true,
	"mozilla corporation":                                true,
	"apple inc.":                                         true,
	"adobe inc.":                                         true,
	"adobe systems incorporated":                         true,
	"valve corp.":                                        true,
	"valve corporation":                                  true,
	"nvidia corporation":                                 true,
	"intel corporation":                                  true,
	"advanced micro devices, inc.":                       true,
	"dell inc":                                           true,
	"dell technologies inc.":                             true,
	"hp inc.":                                            true,
	"lenovo":                                             true,
	"logitech inc":                                       true,
	"discord inc.":                                       true,
	"spotify ab":                                         true,
	"dropbox, inc":                                       true,
	"slack technologies, inc.":                           true,
	"zoom video communications, inc.":                    true,
	"brave software, inc.":                               true,
	"opera norway as":                                    true,
	"vivaldi technologies as":                            true,
	"jetbrains s.r.o.":                                   true,
	"oracle america, inc.":                               true,
	"epic games, inc.":                                   true,
	"blizzard entertainment, inc.":                       true,
	"riot games, inc.":                                   true,
	"agilebits inc.":                                     true,
}

// TrustedSigner reports whether a verified signature belongs to a publisher
// whose ordinary behaviour is uninteresting. Comparison is exact after
// normalising case and whitespace.
func TrustedSigner(signer string) bool {
	return trustedSigners[strings.ToLower(strings.Join(strings.Fields(signer), " "))]
}

// Key identifies what a user is allowing: this rule, for this program, to this
// destination. Allowing "chrome.exe -> googleapis.com" must not silence
// "chrome.exe -> anywhere else".
func Key(ruleID, image, dest string) string {
	return strings.ToLower(ruleID + "|" + image + "|" + dest)
}

// Allow records a user's decision to stop being told about a specific
// rule/program/destination combination.
func (s *Suppressor) Allow(ruleID, image, dest string) {
	s.mu.Lock()
	s.allow[Key(ruleID, image, dest)] = true
	s.mu.Unlock()
}

// AddKeys restores allow decisions persisted from a previous run.
func (s *Suppressor) AddKeys(keys []string) {
	s.mu.Lock()
	for _, k := range keys {
		s.allow[k] = true
	}
	s.mu.Unlock()
}

// Allowed reports whether the user has already allowed this exact combination.
func (s *Suppressor) Allowed(ruleID, image, dest string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allow[Key(ruleID, image, dest)]
}

// Observe records that a program has been seen, establishing its install time
// for the learning window.
func (s *Suppressor) Observe(image string, at time.Time) {
	if image == "" {
		return
	}
	s.mu.Lock()
	if _, ok := s.firstSeen[image]; !ok {
		s.firstSeen[image] = at
	}
	s.mu.Unlock()
}

// InLearningWindow reports whether a program is still in its post-install grace
// period.
func (s *Suppressor) InLearningWindow(image string, now time.Time) bool {
	s.mu.RLock()
	first, ok := s.firstSeen[image]
	s.mu.RUnlock()
	return ok && now.Sub(first) < s.learningWindow
}

// Verdict explains a suppression decision, so the UI and logs can say why
// something did NOT alert — silent suppression is how a detector's failure
// goes unnoticed for months.
type Verdict struct {
	Suppressed bool
	Reason     string
}

// Check applies every gate to a detection.
func (s *Suppressor) Check(d Detection, subj Subject, now time.Time) Verdict {
	image := subj.Conn.Image
	dest := subj.Domain
	if dest == "" {
		dest = subj.Conn.RemoteIP
	}

	// A user's explicit "always allow" outranks everything. If they were wrong,
	// they can undo it — but nagging after an allow destroys trust fastest.
	if s.Allowed(d.Rule.ID, image, dest) {
		return Verdict{true, "you chose to always allow this"}
	}

	sev := d.Rule.Severity

	// Critical findings are never suppressed by trust or newness. A verified
	// publisher signature does not make contacting known malware control
	// infrastructure acceptable.
	if sev == "critical" {
		return Verdict{}
	}

	// A verified signature from a known publisher clears low/medium behavioural
	// noise, which is most of what a normal desktop generates.
	if TrustedSigner(subj.Event.Signer) && subj.Event.Signed && sev != "high" {
		return Verdict{true, "signed by a publisher you already trust"}
	}

	// Newly installed software is noisy by nature; hold non-high findings
	// during its grace period rather than teaching users that installing
	// anything produces warnings.
	if sev != "high" && s.InLearningWindow(image, now) {
		return Verdict{true, "this program was just installed and is still setting itself up"}
	}

	return Verdict{}
}
