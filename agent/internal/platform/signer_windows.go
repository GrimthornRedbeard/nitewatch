//go:build windows

package platform

import (
	"os/exec"
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
// Uses PowerShell's Get-AuthenticodeSignature rather than binding wintrust
// directly: the check runs rarely (once per binary, cached), correctness
// matters more than speed here, and the API surface for full chain validation
// is large enough that a wrong binding would silently report "unsigned" — the
// dangerous direction, since suppression rules trust signatures.
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

func checkSignature(path string) signerResult {
	// -LiteralPath so paths containing [ ] are not treated as wildcards.
	script := `$ErrorActionPreference='Stop';` +
		`$s = Get-AuthenticodeSignature -LiteralPath ` + quotePS(path) + `;` +
		`if ($s.Status -eq 'Valid') { 'VALID|' + $s.SignerCertificate.Subject } else { 'INVALID|' }`

	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script).Output()
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

func quotePS(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
