//go:build windows

package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
)

// FileIdentity is everything the machine itself can say about a program file,
// for somebody trying to establish whether it is what it claims to be.
//
// All of it is read locally. Nothing here contacts anybody: the point is to
// hand the user facts they can check themselves, not to phone a reputation
// service on their behalf.
type FileIdentity struct {
	Path        string `json:"path"`
	SizeBytes   int64  `json:"sizeBytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Company     string `json:"company,omitempty"`
	Product     string `json:"product,omitempty"`
	FileVersion string `json:"fileVersion,omitempty"`
	Description string `json:"description,omitempty"`
	Err         string `json:"error,omitempty"`
}

// versionScript reads the file's embedded version resource — the same
// information the Details tab of a file's Properties window shows. Attacker
// controlled text never enters the script; the path arrives by environment.
const versionScript = `$ErrorActionPreference='SilentlyContinue'
$p = $env:NW_TARGET_PATH
$i = (Get-Item -LiteralPath $p).VersionInfo
'C|' + $i.CompanyName
'P|' + $i.ProductName
'V|' + $i.FileVersion
'D|' + $i.FileDescription`

// Identify gathers what can be learned about a file without asking anyone else.
//
// The hash is the useful part: it is the thing a person can paste into a
// reputation service themselves, on a machine of their choosing, without this
// program deciding to send anything anywhere.
func Identify(path string) FileIdentity {
	id := FileIdentity{Path: path}
	if path == "" {
		id.Err = "no path"
		return id
	}
	st, err := os.Stat(path)
	if err != nil {
		id.Err = "the file could not be read: " + err.Error()
		return id
	}
	id.SizeBytes = st.Size()

	if sum, err := hashFile(path); err == nil {
		id.SHA256 = sum
	} else {
		id.Err = "the file could not be read: " + err.Error()
	}

	out, err := runVersionScript(path)
	if err != nil {
		return id
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 2 {
			continue
		}
		val := strings.TrimSpace(line[2:])
		switch line[0] {
		case 'C':
			id.Company = val
		case 'P':
			id.Product = val
		case 'V':
			id.FileVersion = val
		case 'D':
			id.Description = val
		}
	}
	return id
}

// runVersionScript executes the reader with the path supplied by environment,
// never interpolated — see FileSigner for why that distinction is load-bearing
// when this runs elevated against user-controlled paths.
func runVersionScript(path string) (string, error) {
	cmd := exec.Command(system32("WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", versionScript)
	cmd.Env = append(os.Environ(), "NW_TARGET_PATH="+path)
	out, err := cmd.Output()
	return string(out), err
}

// hashFile streams the file rather than reading it whole: some of these are
// hundreds of megabytes and this runs on a user's machine while they wait.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
