package detect

import (
	"math"
	"sort"
	"sync"
	"time"
)

// BeaconTracker looks for connections on a metronome.
//
// Remote-control malware has to ask its operator for instructions, and it does
// so on a timer. That rhythm is visible through any amount of encryption: you
// cannot read the check-in, but you can see that it happens every sixty seconds
// and has done so forty times. Legitimate software polls too, which is why the
// bar here is regularity rather than frequency — humans and event-driven
// software produce irregular traffic; a scheduler produces a metronome.
type BeaconTracker struct {
	mu sync.Mutex
	// flows maps program+destination to the times it was contacted.
	flows      map[string]*beaconFlow
	maxTracked int
}

type beaconFlow struct {
	times   []time.Time
	updated time.Time
	// alerted stops one steady beacon producing an alert on every subsequent
	// check-in for as long as it keeps running.
	alerted bool
}

const (
	// MinBeaconSamples: the number of check-ins needed before regularity means
	// anything.
	//
	// Set from measurement, not intuition. Against 300 synthetic sequences of
	// irregular human-paced browsing (gaps uniform over 6s-5min), the false
	// alarm rate was: 8 samples 8/300, 10 samples 3/300, 12 samples 1/300,
	// 15 samples 0/300. Chance regularity in a short run is real, and the cost
	// of waiting is only that a beacon is caught on its fifteenth check-in
	// rather than its eighth — fifteen minutes for a one-minute beacon.
	MinBeaconSamples = 15
	// MaxBeaconJitter: how much the interval may vary and still count as a
	// metronome, as a fraction of the mean. Real C2 adds jitter deliberately to
	// defeat exactly this test, so the bar cannot be too tight; ordinary
	// human-driven traffic is far more variable than 25%.
	MaxBeaconJitter = 0.25
	// BeaconMinInterval is the floor below which regularity means nothing.
	//
	// Raised from 5s to 30s after a signed desktop app checking in with its own
	// vendor every 6.8 seconds was reported as command-and-control. Sub-30s
	// polling is what heartbeats, presence channels, telemetry flushes and
	// streaming keepalives look like — the interval is short precisely because
	// the traffic is expected and cheap.
	//
	// Real implants sit at the other end of the range: sleep intervals are
	// conventionally tens of seconds to hours, because a fast beacon is a loud
	// beacon and operators tune for patience. Anything trying to hide is
	// already above this floor, so raising it costs almost no detection and
	// removes an entire class of false alarm.
	BeaconMinInterval = 30 * time.Second
	// BeaconMaxInterval bounds how patient we are. Beyond this the window of
	// observation needed makes the finding unreliable.
	BeaconMaxInterval = 30 * time.Minute
	// beaconHistory caps retained timestamps per flow.
	beaconHistory = 64
)

func NewBeaconTracker() *BeaconTracker {
	return &BeaconTracker{flows: map[string]*beaconFlow{}, maxTracked: 512}
}

// Beacon describes a detected rhythm.
type Beacon struct {
	Interval time.Duration
	Samples  int
	Jitter   float64
}

// Observe records a contact and reports a rhythm if one has emerged.
func (t *BeaconTracker) Observe(key string, at time.Time) (Beacon, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, ok := t.flows[key]
	if !ok {
		if len(t.flows) >= t.maxTracked {
			t.evictOldestLocked()
		}
		f = &beaconFlow{}
		t.flows[key] = f
	}
	f.updated = at

	// Ignore repeats inside the minimum interval: a burst of packets is one
	// conversation, not a series of check-ins.
	if n := len(f.times); n > 0 && at.Sub(f.times[n-1]) < BeaconMinInterval {
		return Beacon{}, false
	}
	f.times = append(f.times, at)
	if len(f.times) > beaconHistory {
		f.times = f.times[len(f.times)-beaconHistory:]
	}
	if len(f.times) < MinBeaconSamples || f.alerted {
		return Beacon{}, false
	}

	b, ok := analyseRhythm(f.times)
	if !ok {
		return Beacon{}, false
	}
	f.alerted = true
	return b, true
}

// analyseRhythm reports whether a series of contacts is regular enough to be a
// schedule rather than a person.
func analyseRhythm(times []time.Time) (Beacon, bool) { return analyseRhythmN(times, MinBeaconSamples) }

func analyseRhythmN(times []time.Time, minSamples int) (Beacon, bool) {
	if len(times) < minSamples {
		return Beacon{}, false
	}
	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	gaps := make([]float64, 0, len(sorted)-1)
	var sum float64
	for i := 1; i < len(sorted); i++ {
		g := sorted[i].Sub(sorted[i-1]).Seconds()
		if g <= 0 {
			continue
		}
		gaps = append(gaps, g)
		sum += g
	}
	if len(gaps) < minSamples-1 {
		return Beacon{}, false
	}

	mean := sum / float64(len(gaps))
	if mean < BeaconMinInterval.Seconds() || mean > BeaconMaxInterval.Seconds() {
		return Beacon{}, false
	}

	// Coefficient of variation: standard deviation relative to the mean, so the
	// test means the same thing for a 10-second beacon and a 10-minute one.
	var sq float64
	for _, g := range gaps {
		d := g - mean
		sq += d * d
	}
	jitter := math.Sqrt(sq/float64(len(gaps))) / mean
	if jitter > MaxBeaconJitter {
		return Beacon{}, false
	}

	return Beacon{
		Interval: time.Duration(mean * float64(time.Second)),
		Samples:  len(sorted),
		Jitter:   jitter,
	}, true
}

// Forget drops a flow's history.
func (t *BeaconTracker) Forget(key string) {
	t.mu.Lock()
	delete(t.flows, key)
	t.mu.Unlock()
}

func (t *BeaconTracker) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, f := range t.flows {
		if oldest.IsZero() || f.updated.Before(oldest) {
			oldest, oldestKey = f.updated, k
		}
	}
	delete(t.flows, oldestKey)
}

// detectBeaconing fires when a program contacts one destination on a schedule.
func detectBeaconing(s Subject, e *Engine) map[string]any {
	if e.beacon == nil || s.Conn.Inbound || s.Conn.Image == "" {
		return nil
	}
	// Shared infrastructure hosts update checks, telemetry and push channels,
	// all of which poll on timers by design. Regularity there is the product
	// working, not a signal.
	if SharedInfrastructure(s.Recon.Org) {
		return nil
	}
	// A signed program talking to its own publisher's network is a desktop app
	// polling its backend, which is what chat clients, mail clients, AI
	// assistants and game launchers do all day. Calling that "how remote-control
	// malware stays in touch" is both wrong and frightening.
	//
	// Deliberately NOT "signed is enough": certificates get stolen, and a signed
	// implant checking in with somebody else's server is precisely what this
	// detector is for. The publisher must also own the far end.
	if s.Event.Signed && SignerMatchesOrg(s.Event.Signer, s.Recon.Org) {
		return nil
	}
	// A Store app polling on a timer is a Store app working. The package is
	// signed and Microsoft-vetted even though the .exe carries no embedded
	// signature for SignerMatchesOrg to compare.
	if ClassifyInstall(s.Conn.Image, s.Event.Signed, s.Event.Signer).Store {
		return nil
	}
	dest := s.Domain
	if dest == "" {
		dest = s.Conn.RemoteIP
	}
	b, ok := e.beacon.Observe(s.Conn.Image+"|"+dest, s.Conn.LastSeen)
	if !ok {
		return nil
	}
	return map[string]any{
		"BeaconInterval": humanInterval(b.Interval),
		"BeaconSamples":  b.Samples,
	}
}

func humanInterval(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return fmtFloat(d.Hours()) + " hours"
	case d >= time.Minute:
		return fmtFloat(d.Minutes()) + " minutes"
	}
	return fmtFloat(d.Seconds()) + " seconds"
}
