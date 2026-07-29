// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	signerMu    sync.RWMutex
	signerCache = map[string]signerResult{}
)

type signerResult struct {
	signed bool
	signer string
}

// FileSigner reports whether an executable carries a valid Authenticode
// signature and, if so, the subject name of the signing certificate.
//
// SECURITY: the path is passed through an ENVIRONMENT VARIABLE, never
// interpolated into the script text. Quoting a path into a PowerShell string
// cannot be made safe by escaping U+0027 alone — the tokenizer also accepts
// U+2018, U+2019, U+201A and U+201B as string delimiters, so a filename
// containing a Unicode right-quote closes the literal and everything after it
// executes. This runs elevated against paths an UNPRIVILEGED user controls
// (registry Run values, dropped executables), so that was a local privilege
// escalation to SYSTEM. Environment variables are read as data by $env: and are
// never parsed as code, which removes the bug class rather than patching one
// character.
//
// Uses PowerShell rather than binding wintrust directly: the check runs rarely
// (once per binary, cached), and a wrong binding would silently report
// "unsigned" — the dangerous direction, since suppression rules trust
// signatures.
//
// Only status "Valid" counts as signed. A present-but-untrusted or tampered
// signature is NOT a signature.
func FileSigner(path string) (bool, string) {
	if path == "" {
		return false, ""
	}
	signerMu.RLock()
	if r, ok := signerCache[path]; ok {
		signerMu.RUnlock()
		return r.signed, r.signer
	}
	signerMu.RUnlock()

	r := checkSignature(path)

	signerMu.Lock()
	signerCache[path] = r
	signerMu.Unlock()
	return r.signed, r.signer
}

// sigScript reads its input from the ENVIRONMENT, so no attacker-controlled
// text ever becomes part of the script.
const sigScript = `$ErrorActionPreference='Stop'
$p = $env:NW_TARGET_PATH
$s = Get-AuthenticodeSignature -LiteralPath $p
if ($s.Status -eq 'Valid') { 'VALID|' + $s.SignerCertificate.Subject } else { 'INVALID|' }`

func checkSignature(path string) signerResult {
	cmd := exec.Command(system32("WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", sigScript)
	cmd.Env = append(os.Environ(), "NW_TARGET_PATH="+path)

	out, err := cmd.Output()
	if err != nil {
		return signerResult{} // unreadable: treat as unsigned, never as trusted
	}

	line := strings.TrimSpace(string(out))
	if !strings.HasPrefix(line, "VALID|") {
		return signerResult{}
	}
	return signerResult{signed: true, signer: commonName(strings.TrimPrefix(line, "VALID|"))}
}

// commonName pulls CN= out of a certificate subject, which is the publisher
// name a person would recognise.
func commonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.Trim(part[3:], `"`)
		}
	}
	return strings.TrimSpace(subject)
}

// system32 builds an absolute path under the real system directory. An elevated
// process must not resolve helper binaries through %PATH%: a user-writable
// directory on the path (which third-party installers add routinely) would let
// an unprivileged user plant powershell.exe and have us run it as SYSTEM.
func system32(parts ...string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(append([]string{root, "System32"}, parts...)...)
}
