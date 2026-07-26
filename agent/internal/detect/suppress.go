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

// trustedSigners are publishers whose signed binaries do not warrant
// low-severity behavioural alerts. Signature verification is the strong claim
// here — this list only decides whose VERIFIED signature is boring.
//
// Deliberately conservative: a signed binary from one of these publishers can
// still raise a Critical feed hit. Being signed by Microsoft does not make
// contacting known malware infrastructure acceptable; it makes an unremarkable
// first connection unremarkable.
var trustedSigners = []string{
	"microsoft",
	"google",
	"mozilla",
	"apple",
	"adobe",
	"valve",
	"nvidia",
	"intel",
	"amd",
	"dell",
	"hp inc",
	"lenovo",
	"logitech",
	"discord",
	"spotify",
	"dropbox",
	"slack technologies",
	"zoom video communications",
	"brave software",
	"opera",
	"vivaldi",
	"jetbrains",
	"oracle",
	"steam",
	"epic games",
	"blizzard",
	"riot games",
	"1password",
	"agilebits",
}

// TrustedSigner reports whether a verified signature belongs to a publisher
// whose ordinary behaviour is uninteresting.
func TrustedSigner(signer string) bool {
	if signer == "" {
		return false
	}
	s := strings.ToLower(signer)
	for _, t := range trustedSigners {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
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
