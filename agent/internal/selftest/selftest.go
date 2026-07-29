// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package selftest proves the alerting machinery works, on demand, without
// waiting for something bad to happen.
//
// "Is this thing even on?" is a fair question to ask of security software that
// is quiet by design. A tool that has said nothing for a week is either
// protecting you or broken, and from the outside those look identical. This is
// the answer: press a button, watch every alert the product can raise appear,
// read what each one means, then clear them away.
//
// WHAT THIS DOES AND DOES NOT PROVE — stated plainly, because a self-test that
// overstates its own coverage is worse than none.
//
// It DOES exercise, for real: every shipped rule, the template rendering that
// turns a rule into a sentence, the playbook, the suppression gate, the
// evidence fields, the ledger write, the API, the response actions the UI
// offers, and the rendering of all of it on screen. If a rule is broken,
// mis-worded, or missing its buttons, this shows it.
//
// It does NOT exercise the sensor. These findings are constructed in memory and
// handed to the rule engine directly; nothing is read from ETW, no file is
// touched, no process is started, and no connection is made. A green self-test
// means "the alerting works", not "the watching works". The status banner on the
// dashboard is what tells you telemetry is flowing.
//
// Every finding it produces is marked as a drill and is visibly labelled as one
// in the UI, because a person who sees "your files are being encrypted" and
// later learns it was a test will not trust the next one.
package selftest

import (
	"fmt"
	"strings"
	"time"

	"github.com/threattape/nitewatch/agent/internal/autostart"
	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/filewatch"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
)

// DrillField marks an alert as produced by the self-test. Present in the
// evidence so it survives into the ledger and reaches the UI.
const DrillField = "Drill"

// Fake names used throughout, chosen so nothing can be mistaken for a real
// program or a real address on the user's machine.
//
// Addresses come from the ranges RFC 5737 and RFC 3849 reserve for
// documentation. They are not routable and belong to nobody, so a drill can
// never name a real person's server, and a user who looks one up finds an RFC
// rather than somebody's business.
const (
	drillDir  = `C:\NiteWatch-SelfTest\`
	drillExe  = drillDir + `not-a-real-program.exe`
	drillIPv4 = "203.0.113.13" // TEST-NET-3
	drillIPv6 = "2001:db8::13" // documentation prefix
	drillHost = "selftest.invalid"
)

// Scenario is one thing the self-test makes the product say, together with the
// explanation shown beside it.
type Scenario struct {
	// RuleID is the rule this is meant to trip. Used to verify coverage.
	RuleID string `json:"ruleId"`
	// Title is the short name of the situation, for the explanation list.
	Title string `json:"title"`
	// Real describes what would actually be happening on the computer for this
	// alert to appear for real. This is the part that answers "what is my
	// computer doing?" rather than "what does the tool call it".
	Real string `json:"real"`
	// Why explains why that is worth telling somebody about.
	Why string `json:"why"`
	// Fired reports whether the rule actually produced a finding.
	Fired bool `json:"fired"`
	// Skipped marks a scenario that could not run because a feature it depends
	// on is switched off. Not a fault, and reported separately from one — a
	// user who turned threat feeds off should be told that, not shown a
	// failure they cannot act on.
	Skipped bool   `json:"skipped,omitempty"`
	Skip    string `json:"skip,omitempty"`
}

// Result is the outcome of a run.
type Result struct {
	Scenarios []Scenario `json:"scenarios"`
	Fired     int        `json:"fired"`
	Expected  int        `json:"expected"`
	Skipped   int        `json:"skipped,omitempty"`
	// Missing lists rules that were expected to fire and did not. A non-empty
	// list is a real failure — a rule that cannot be triggered by its own
	// scenario is a rule that will not fire in the field either.
	Missing []string `json:"missing,omitempty"`
}

// OK reports whether every scenario produced its alert.
func (r Result) OK() bool { return len(r.Missing) == 0 && r.Fired == r.Expected }

// Recorder is the subset of the ledger the self-test writes through.
type Recorder interface {
	RecordAlert(a ledger.Alert) (bool, error)
}

// Run builds every scenario, evaluates it against the live rule engine, and
// records whatever fires as a drill.
//
// The engine is the real one, loaded with the real shipped packs. Nothing here
// is stubbed: if a rule has been edited into a state where it no longer
// matches, this reports it as missing rather than quietly passing.
func Run(e *detect.Engine, feeds *intel.Store, rec Recorder, now time.Time) (Result, error) {
	res := Result{}
	seen := map[string]bool{}
	prime(e, feeds, now)

	record := func(sc Scenario, dets []detect.Detection) Scenario {
		for _, d := range dets {
			if d.Rule.ID != sc.RuleID {
				continue // another rule also matched; only score the intended one
			}
			sc.Fired = true
			seen[d.Rule.ID] = true
			if rec != nil {
				fields := map[string]any{}
				for k, v := range d.Fields {
					fields[k] = v
				}
				fields[DrillField] = true
				_, _ = rec.RecordAlert(ledger.Alert{
					Time: now, RuleID: d.Rule.ID, Area: string(d.Rule.Area),
					Severity:  string(d.Rule.Severity),
					Title:     d.Rule.RenderTitle(fields),
					Narrative: d.Rule.RenderNarrative(fields),
					Playbook:  d.Rule.RenderPlaybook(fields),
					Evidence:  fields,
				})
			}
		}
		return sc
	}

	feedsReady := feeds != nil
	for _, s := range connectionScenarios(now) {
		subj := s.Subject
		if s.RuleID == "c2-feed-flagged-connection" && !feedsReady {
			sc := s.Scenario
			sc.Skipped = true
			sc.Skip = "Threat feeds are switched off, so there is no list to match against. " +
				"Start the agent without --no-feeds to include this one."
			res.Scenarios = append(res.Scenarios, sc)
			continue
		}
		// The beacon detector needs a rhythm, not a single contact. Feed the
		// tracker the earlier check-ins so the final evaluation sees a pattern
		// exactly as it would after a real program had been running a while.
		if s.RuleID == "c2-beaconing" {
			// One fewer than the minimum: the tracker fires on the sample that
			// reaches the threshold and then latches, so the scored evaluation
			// below must be the one that completes the rhythm.
			for i := 0; i < detect.MinBeaconSamples-1; i++ {
				warm := subj
				// Evenly spaced right up to `now`, so the scored evaluation lands
				// exactly one gap after the last warm-up and the rhythm is
				// perfect. An off-by-one here leaves a double gap at the end,
				// which reads as jitter and the pattern never trips.
				warm.Conn.LastSeen = now.Add(-time.Duration(detect.MinBeaconSamples-1-i) * beaconGap)
				e.Evaluate(warm)
			}
		}
		res.Scenarios = append(res.Scenarios, record(s.Scenario, e.Evaluate(subj)))
	}
	for _, s := range fileScenarios(now) {
		res.Scenarios = append(res.Scenarios, record(s.Scenario, e.EvaluateFile(s.Subject)))
	}
	for _, s := range persistScenarios() {
		res.Scenarios = append(res.Scenarios, record(s.Scenario, e.EvaluatePersistence(s.Subject)))
	}

	for i := range res.Scenarios {
		sc := &res.Scenarios[i]
		if sc.Skipped {
			res.Skipped++
			continue
		}
		res.Expected++
		if sc.Fired {
			res.Fired++
		} else {
			res.Missing = append(res.Missing, sc.RuleID)
		}
	}
	return res, nil
}

// beaconGap is the spacing used to establish the drill's rhythm. Comfortably
// above BeaconMinInterval so the scenario keeps working if that floor moves
// again.
const beaconGap = 2 * time.Minute

// prime sets up the state the detectors read from but that a Subject cannot
// carry: the threat-intel entry for the drill address, and the record of a
// secret having just been read.
//
// The intel entry is added to the live store. That is deliberate — it makes the
// feed-matching path genuinely exercised rather than mocked — and it is safe
// because the address is TEST-NET-3, which is reserved for documentation and
// routes nowhere. It lives in memory only and is gone on restart.
func prime(e *detect.Engine, feeds *intel.Store, now time.Time) {
	if feeds != nil {
		_ = feeds.LoadList(strings.NewReader(drillIPv4+"\n"), intel.Source{
			Name:       "NiteWatch self-test",
			Kind:       intel.KindIP,
			Confidence: intel.Malicious,
			Reason:     "a drill entry added by the self-test, not a real report",
		})
	}
	if ex := e.Exfil(); ex != nil {
		ex.NoteSensitiveRead(424242, "a saved-password file",
			`C:\NiteWatch-SelfTest\Login Data`, now)
	}
}

type connScenario struct {
	Scenario
	Subject detect.Subject
}

type fileScenario struct {
	Scenario
	Subject detect.FileSubject
}

type persistScenario struct {
	Scenario
	Subject detect.PersistSubject
}

// baseConn is an unsigned program in an obviously fake directory reaching a
// documentation address. Every connection scenario starts here and changes only
// what its own rule needs, so each one tests one thing.
func baseConn(now time.Time) detect.Subject {
	return detect.Subject{
		// Kind matters: detectUnsignedOutbound checks it, so a subject without
		// it silently skips that rule.
		Event: event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn: ledger.Connection{
			PID: 424242, Image: drillExe, RemoteIP: drillIPv4, RemotePort: 443,
			Proto: "TCP", Time: now, LastSeen: now,
		},
		Recon:        recon.Info{ASN: 64511, Org: "EXAMPLE-SELFTEST-NET", Country: "US"},
		FirstContact: true,
	}
}

func connectionScenarios(now time.Time) []connScenario {
	var out []connScenario

	// 1. A destination on a public malware feed.
	fl := baseConn(now)
	fl.Domain = drillHost
	out = append(out, connScenario{Scenario{
		RuleID: "c2-feed-flagged-connection",
		Title:  "Talking to a known-bad address",
		Real:   "A program on your computer opened a connection to a server that appears on a public list of addresses used by malware.",
		Why:    "Somebody else already caught this address doing harm and published it. That is about as close to certainty as this kind of tool gets.",
	}, fl})

	// 2. Connecting to a bare number with no lookup first.
	raw := baseConn(now)
	out = append(out, connScenario{Scenario{
		RuleID: "c2-raw-ip-no-dns",
		Title:  "Dialling a number instead of a name",
		Real:   "A program connected straight to a numeric address without first asking for it by name — the way you might dial a phone number from memory rather than looking up a contact.",
		Why:    "Ordinary software asks for servers by name. Skipping that step, from a program with no verified publisher, is a small oddity worth a glance — not proof of anything.",
	}, raw})

	// 3. Unsigned software reaching the internet for the first time.
	un := baseConn(now)
	un.Domain = drillHost
	un.HadDNS = true
	out = append(out, connScenario{Scenario{
		RuleID: "c2-unsigned-first-contact",
		Title:  "Unidentified software going online",
		Real:   "A program with no digital signature — meaning Windows cannot confirm who wrote it — contacted the internet for the first time.",
		Why:    "Plenty of small or homemade tools are unsigned, so this is a prompt to look rather than a verdict. Where the program lives matters as much as its name.",
	}, un})

	// 4. First contact with an unexpected country.
	fo := baseConn(now)
	fo.Recon.Country = "RU"
	fo.Recon.Org = "EXAMPLE-SELFTEST-HOSTING"
	fo.Domain = drillHost
	fo.HadDNS = true
	out = append(out, connScenario{Scenario{
		RuleID: "c2-foreign-first-contact",
		Title:  "First contact with an unusual country",
		Real:   "A program contacted a server in a country your computer does not normally talk to.",
		Why:    "On its own this means very little — services are hosted everywhere. It matters in combination with the other things on this list.",
	}, fo})

	// 5. An upload straight after reading secrets. The strongest signal here.
	ex := baseConn(now)
	ex.Conn.PID = 424242 // must match the PID primed in prime()
	ex.Conn.BytesSent = 40 << 20
	ex.Domain = drillHost
	ex.HadDNS = true
	out = append(out, connScenario{Scenario{
		RuleID: "c2-exfil-after-secret-read",
		Title:  "Secrets read, then a large upload",
		Real:   "A program opened a file that stores saved passwords, and moments later sent a large amount of data out to the internet.",
		Why:    "The upload is encrypted and cannot be read — it does not need to be. Something took your secrets and then sent something of about that size to somebody else. This is the most serious pattern the product looks for.",
	}, ex})

	// 6. Connections on a metronome. Fed enough samples to trip the tracker.
	out = append(out, connScenario{Scenario{
		RuleID: "c2-beaconing",
		Title:  "Checking in on a timer",
		Real:   "A program connected to the same address again and again at almost exactly the same interval, like an alarm clock going off.",
		Why:    "Remote-control software asks its operator for instructions on a schedule. Plenty of ordinary software polls on a timer too, so the question is whether you recognise the program — which is why signed software talking to its own publisher is not reported.",
	}, beaconSubject(now)})

	return out
}

// beaconSubject is a marker; Run replays it through the tracker enough times to
// establish a rhythm. Kept separate because it is the one scenario that needs
// repetition rather than a single evaluation.
func beaconSubject(now time.Time) detect.Subject {
	s := baseConn(now)
	// Its own program and destination, so it gets its own entry in the beacon
	// tracker. Sharing a key with the earlier scenarios put a "just now"
	// timestamp in the flow before the warm-up ran, and every backdated sample
	// was then discarded as sub-interval chatter — the rhythm never formed.
	s.Conn.Image = drillDir + `beacon-drill.exe`
	s.Conn.PID = 424246
	s.Domain = "beacon." + drillHost
	s.HadDNS = true
	return s
}

func fileScenarios(now time.Time) []fileScenario {
	var out []fileScenario

	sample := []string{"holiday-photos.jpg", "tax-return-2025.pdf", "invoice.xlsx"}

	// Confirmed encryption: many files, renamed to an unfamiliar type.
	conf := detect.FileSubject{
		PID: 424242, Image: drillExe,
		Burst: filewatch.Burst{
			PID: 424242, Image: drillExe, Files: 180, Renamed: 180, Dirs: 12,
			Oldest: now.Add(-40 * time.Second), Newest: now, Sample: sample,
		},
	}
	out = append(out, fileScenario{Scenario{
		RuleID: "ransomware-confirmed",
		Title:  "Files being encrypted right now",
		Real:   "A program is rewriting large numbers of your documents and photos across many folders, and renaming them to a file type nothing can open.",
		Why:    "This is what ransomware looks like. Files already encrypted cannot be recovered without the attacker's key — but files it has not reached yet can still be saved, which is why the first step is to stop it rather than to investigate.",
	}, conf})

	// Suspected: the same volume, without the renaming.
	susp := detect.FileSubject{
		PID: 424243, Image: drillExe,
		Burst: filewatch.Burst{
			PID: 424243, Image: drillExe, Files: 140, Dirs: 9,
			Oldest: now.Add(-45 * time.Second), Newest: now, Sample: sample,
		},
	}
	out = append(out, fileScenario{Scenario{
		RuleID: "ransomware-suspected",
		Title:  "A lot of files changing very quickly",
		Real:   "A program changed many of your documents in under a minute, spread across several folders.",
		Why:    "Backup tools, cloud sync and photo editors do exactly this, legitimately — and so does ransomware in its first minute. The alert says so, because telling you the difference is your job here, not the tool's.",
	}, susp})

	// Backup destruction.
	bd := detect.FileSubject{
		PID: 424244, Image: drillExe, ToolRun: "vssadmin.exe",
	}
	out = append(out, fileScenario{Scenario{
		RuleID: "ransomware-backup-destruction",
		Title:  "Your ability to recover being deleted",
		Real:   "Something ran the Windows tool that deletes restore points and shadow copies — the snapshots Windows keeps so you can roll back.",
		Why:    "Almost nothing has a legitimate reason to do this. It is the step ransomware takes before encrypting, so you cannot simply restore your way out.",
	}, bd})

	// Credential theft.
	cred := detect.FileSubject{
		PID: 424245, Image: drillExe,
		Path: `C:\Users\SelfTest\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
	}
	out = append(out, fileScenario{Scenario{
		RuleID: "credential-theft",
		Title:  "Something reading your saved passwords",
		Real:   "A program that is not your browser opened the file where your browser keeps saved passwords.",
		Why:    "Chrome reading Chrome's password file is Chrome working. Anything else reading it is how password stealers behave — and they are the most common consumer malware there is.",
	}, cred})

	return out
}

func persistScenarios() []persistScenario {
	var out []persistScenario

	hij := detect.PersistSubject{Change: autostart.Change{Entry: autostart.Entry{
		Kind:     autostart.KindIFEO,
		Location: `HKLM\...\Image File Execution Options\notepad.exe`,
		Name:     "Debugger", Target: drillExe,
	}}}
	out = append(out, persistScenario{Scenario{
		RuleID: "persist-image-hijack",
		Title:  "A program hijacked to launch something else",
		Real:   "A Windows setting was changed so that starting one program silently starts a different one instead.",
		Why:    "This setting exists for developers debugging software. Outside that, it is a way to make a program you trust launch a program you did not choose.",
	}, hij})

	repl := detect.PersistSubject{Change: autostart.Change{
		Entry: autostart.Entry{
			Kind: autostart.KindRunKey, Location: `HKCU\...\Run`,
			Name: "OneDrive", Target: drillExe,
		},
		Previous: `C:\Program Files\Microsoft OneDrive\OneDrive.exe`,
	}}
	out = append(out, persistScenario{Scenario{
		RuleID: "persist-autostart-replaced",
		Title:  "An existing startup entry quietly swapped",
		Real:   "Something that already ran when you switched on your computer was changed to run a different program instead, keeping the old, trusted-looking name.",
		Why:    "A fresh startup entry is what installing software looks like. Editing one that already exists, and keeping its name, is what hiding looks like.",
	}, repl})

	temp := detect.PersistSubject{Change: autostart.Change{Entry: autostart.Entry{
		Kind: autostart.KindRunKey, Location: `HKCU\...\Run`,
		Name: "SelfTestEntry", Target: `C:\Users\SelfTest\AppData\Local\Temp\not-a-real-program.exe`,
	}}}
	out = append(out, persistScenario{Scenario{
		RuleID: "persist-from-temp-location",
		Title:  "Something set to start from a temporary folder",
		Real:   "A program was set to run every time you switch on your computer, from the folder Windows uses for throwaway files.",
		Why:    "Installed software lives in Program Files. The temporary folder is where things land when they arrive from an email or a web page — not where anything you chose to install belongs.",
	}, temp})

	unsigned := detect.PersistSubject{Change: autostart.Change{Entry: autostart.Entry{
		Kind: autostart.KindStartupFolder, Location: `C:\Users\SelfTest\...\Startup`,
		Name: "not-a-real-program.exe", Target: drillExe,
	}}}
	out = append(out, persistScenario{Scenario{
		RuleID: "persist-unsigned-autostart",
		Title:  "Unidentified software added to startup",
		Real:   "A program with no digital signature was set to run automatically every time you switch on your computer.",
		Why:    "Starting with Windows is how software makes sure it keeps running. Combined with having no verifiable publisher, it is worth knowing about.",
	}, unsigned})

	return out
}

// Explain returns the scenario list without running anything, for the UI to
// show before the user commits to generating alerts.
func Explain(now time.Time) []Scenario {
	var out []Scenario
	for _, s := range connectionScenarios(now) {
		out = append(out, s.Scenario)
	}
	for _, s := range fileScenarios(now) {
		out = append(out, s.Scenario)
	}
	for _, s := range persistScenarios() {
		out = append(out, s.Scenario)
	}
	return out
}

// Describe renders a one-line summary, for the log.
func Describe(r Result) string {
	skip := ""
	if r.Skipped > 0 {
		skip = fmt.Sprintf(" (%d skipped)", r.Skipped)
	}
	if r.OK() {
		return fmt.Sprintf("self-test: all %d alerts fired%s", r.Expected, skip)
	}
	return fmt.Sprintf("self-test: %d of %d fired%s; missing %v", r.Fired, r.Expected, skip, r.Missing)
}
