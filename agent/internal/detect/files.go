// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/threattape/nitewatch/agent/internal/filewatch"
)

// FileSubject is file activity awaiting judgement.
type FileSubject struct {
	PID    uint32
	Image  string
	Path   string
	Signed bool
	Signer string
	// Burst is the process's recent activity across user documents.
	Burst filewatch.Burst
	// ToolRun is set when the acting process is a backup-destruction tool.
	ToolRun string
}

// EvaluateFile runs the file-activity detectors.
func (e *Engine) EvaluateFile(s FileSubject) []Detection {
	dets := map[string]func(FileSubject) map[string]any{
		"mass-encryption-confirmed":     detectEncryptionConfirmed,
		"mass-encryption-suspected":     detectEncryptionSuspected,
		"backup-destruction":            detectBackupDestruction,
		"credential-access-by-stranger": detectCredentialTheft,
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
		base := fileFields(s)
		for k, v := range fields {
			base[k] = v
		}
		out = append(out, Detection{Rule: bound[0], Fields: base})
	}
	return out
}

func fileFields(s FileSubject) map[string]any {
	return map[string]any{
		"ProcessName": shortName(s.Image),
		"ImagePath":   s.Image,
		"PID":         s.PID,
		"FileCount":   s.Burst.Files,
		"DirCount":    s.Burst.Dirs,
		"SampleFiles": strings.Join(sampleNames(s.Burst.Sample), ", "),
		"ToolName":    s.ToolRun,
		"SecretPath":  s.Path,
	}
}

// sampleNames shows file NAMES rather than full paths: the user recognises
// "taxes.xlsx", not a path they never look at.
func sampleNames(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Base(strings.ReplaceAll(p, `\`, "/")))
	}
	return out
}

// detectEncryptionConfirmed fires when corroborating evidence removes doubt.
func detectEncryptionConfirmed(s FileSubject) map[string]any {
	if filewatch.Assess(s.Burst) != filewatch.Confirmed {
		return nil
	}
	var why string
	switch {
	case s.Burst.Notes > 0:
		why = "left behind a file demanding payment to get them back"
	case s.Burst.Renamed > 0:
		why = fmt.Sprintf("renamed %d of them to an unfamiliar file type", s.Burst.Renamed)
	default:
		why = "changed them in a pattern typical of encryption"
	}
	return map[string]any{"EvidenceSummary": why}
}

// detectEncryptionSuspected fires on volume alone. Signed software from a
// trusted publisher is exempt: backup and sync tools do exactly this, and
// alerting on every backup would train users to ignore the confirmed case too.
func detectEncryptionSuspected(s FileSubject) map[string]any {
	if filewatch.Assess(s.Burst) != filewatch.Suspicious {
		return nil
	}
	if s.Signed && TrustedSigner(s.Signer) {
		return nil
	}
	return map[string]any{}
}

func detectBackupDestruction(s FileSubject) map[string]any {
	if s.ToolRun == "" {
		return nil
	}
	return map[string]any{}
}

// detectCredentialTheft fires when a program reads a secret store it does not
// own. The owner comparison is the whole rule: Chrome reading Chrome's password
// database is Chrome working.
func detectCredentialTheft(s FileSubject) map[string]any {
	what, owner := filewatch.CredentialInfo(s.Path)
	if what == "" {
		return nil
	}
	// The kernel is not an information stealer. File I/O lands in the System
	// process whenever the cache manager flushes a mapped page, which is
	// routine for a database the owning browser has open.
	if SystemProcess(s.Image) {
		return nil
	}
	reader := strings.ToLower(shortName(s.Image))
	if owner != "" && reader == strings.ToLower(owner) {
		return nil
	}
	// Windows' own components legitimately touch these.
	if pathIsUnderWindows(s.Image) {
		return nil
	}
	// Anti-malware reads every file on the machine; that is the whole job. This
	// used to be covered by the C:\Windows\ check above, which stopped being
	// true when Defender moved to C:\ProgramData\Microsoft\Windows Defender\
	// so its engine could update independently of the OS. A soak duly reported
	// "MsMpEng.exe is reading your Firefox cookies" as critical.
	if SecurityScanner(s.Image, s.Signed, s.Signer) {
		return nil
	}
	// One browser reading another's store is the import feature. Every
	// Chromium-derived browser offers to bring your passwords across, and the
	// same soak flagged Brave sweeping Edge's User Data as an information
	// stealer.
	if BrowserImport(s.Image, s.Signed, s.Signer, owner) {
		return nil
	}
	if s.Signed && TrustedSigner(s.Signer) && owner == "" {
		// A trusted publisher reading a store with no single owner (SSH keys,
		// cloud credentials) is plausible: developer tooling does this.
		return nil
	}

	note := "No other program should need to read it."
	if owner != "" {
		note = fmt.Sprintf("Only %s should be reading it.", owner)
	}
	return map[string]any{"SecretDescription": what, "OwnerNote": note}
}

// pathIsUnderWindows reports whether an image lives in the Windows directory.
//
// Named rather than inlined because it is load-bearing for a suppression that
// silently stopped covering Defender, and a test now pins that fact.
func pathIsUnderWindows(image string) bool {
	return strings.HasPrefix(strings.ToLower(image), `c:\windows\`)
}
