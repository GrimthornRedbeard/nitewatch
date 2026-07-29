// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import (
	"strings"

	"github.com/threattape/nitewatch/agent/internal/autostart"
)

// PersistSubject is an autostart change awaiting judgement.
type PersistSubject struct {
	Change autostart.Change
	// Signed/Signer describe the program the entry will run, when known.
	Signed bool
	Signer string
	// WrittenBy is the process the causal graph blames for the change, when
	// one can be attributed. Empty is common and not itself suspicious: the
	// change may predate the agent starting.
	WrittenBy string
}

// EvaluatePersistence runs the persistence detectors over one autostart change.
func (e *Engine) EvaluatePersistence(s PersistSubject) []Detection {
	dets := map[string]func(PersistSubject) map[string]any{
		"autostart-hijack-mechanism":   detectHijackMechanism,
		"autostart-target-replaced":    detectTargetReplaced,
		"autostart-from-temp-location": detectTempLocation,
		"autostart-unsigned":           detectUnsignedAutostart,
	}
	var out []Detection
	for name, det := range dets {
		bound := e.set.For(name)
		if len(bound) == 0 {
			continue
		}
		fields := det(s)
		if fields == nil {
			continue
		}
		base := persistFields(s)
		for k, v := range fields {
			base[k] = v
		}
		out = append(out, Detection{Rule: bound[0], Fields: base})
	}
	return out
}

func persistFields(s PersistSubject) map[string]any {
	e := s.Change.Entry
	target := autostart.TargetPath(e.Target)
	return map[string]any{
		"ProgramName":          shortName(target),
		"Target":               e.Target,
		"TargetPath":           target,
		"EntryName":            e.Name,
		"Location":             e.Location,
		"Mechanism":            string(e.Kind),
		"MechanismDescription": e.Kind.Describe(),
		"PreviousTarget":       s.Change.Previous,
		"WrittenBy":            shortName(s.WrittenBy),
		"HijackedProgram":      e.Name,
		"LocationKind":         describeLocation(target),
	}
}

// detectHijackMechanism fires on mechanisms legitimate consumer software
// essentially never uses — hijacking another program's launch, or loading into
// every process. These exist to hide.
func detectHijackMechanism(s PersistSubject) map[string]any {
	if !s.Change.Entry.Kind.Suspicious() {
		return nil
	}
	// Winlogon holds legitimate defaults (explorer.exe, userinit.exe); only a
	// change away from those is interesting, and that is the replacement rule.
	if s.Change.Entry.Kind == autostart.KindWinlogon && s.Change.Previous == "" {
		return nil
	}
	return map[string]any{}
}

// detectTargetReplaced fires when an existing autostart entry's target changed:
// inheriting the trust already placed in another program.
func detectTargetReplaced(s PersistSubject) map[string]any {
	if s.Change.Previous == "" {
		return nil
	}
	return map[string]any{}
}

// suspiciousDirs are locations installed software does not live in. A program
// running from here AND registering autostart is behaving like a bad download.
var suspiciousDirs = []string{
	`\appdata\local\temp\`,
	`\appdata\roaming\`,
	`\appdata\local\`,
	`\downloads\`,
	`\windows\temp\`,
	`\temp\`,
	`\public\`,
	`\programdata\`,
}

func describeLocation(target string) string {
	t := strings.ToLower(target)
	switch {
	case strings.Contains(t, `\downloads\`):
		return "your Downloads folder"
	case strings.Contains(t, `\temp\`):
		return "a temporary folder"
	case strings.Contains(t, `\appdata\`):
		return "a hidden application-data folder"
	case strings.Contains(t, `\public\`):
		return "the Public folder"
	case strings.Contains(t, `\programdata\`):
		return "the ProgramData folder"
	}
	return "an unusual location"
}

func inSuspiciousDir(target string) bool {
	t := strings.ToLower(target)
	for _, d := range suspiciousDirs {
		if strings.Contains(t, d) {
			return true
		}
	}
	return false
}

func detectTempLocation(s PersistSubject) map[string]any {
	target := autostart.TargetPath(s.Change.Entry.Target)
	if target == "" || !inSuspiciousDir(target) {
		return nil
	}
	// A signed program from a trusted publisher in AppData is normal for
	// several mainstream apps (browsers and chat clients install per-user).
	if s.Signed && TrustedSigner(s.Signer) {
		return nil
	}
	return map[string]any{}
}

// detectUnsignedAutostart is the catch-all: something unsigned now starts with
// Windows. Medium severity — informative, not alarming.
func detectUnsignedAutostart(s PersistSubject) map[string]any {
	if s.Signed {
		return nil
	}
	target := autostart.TargetPath(s.Change.Entry.Target)
	if target == "" {
		return nil
	}
	// Windows' own components are not "unsigned" in any meaningful sense even
	// when we could not read a signature.
	if strings.HasPrefix(strings.ToLower(target), `c:\windows\`) {
		return nil
	}
	return map[string]any{}
}
