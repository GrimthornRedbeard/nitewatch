// Package respond executes remediation on the user's behalf.
//
// Everything here changes the machine, so three rules hold throughout:
//
//  1. Nothing runs without an explicit user click. There is no auto-response.
//     A false positive that kills a process the user needed is a worse outcome
//     than the malware we were guessing about.
//  2. Every action is recorded before and after it runs, with enough detail to
//     undo it. An action nobody can reverse is one nobody should have taken.
//  3. Actions use ordinary OS facilities — no kernel driver, no injection.
//     The user could have done each of these by hand; we are saving them the
//     research, not gaining privileges they lack.
package respond

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Kind identifies what an action does.
type Kind string

const (
	KillProcess     Kind = "kill-process"
	BlockAddress    Kind = "block-address"
	QuarantineFile  Kind = "quarantine-file"
	RemoveAutostart Kind = "remove-autostart"
)

// Action is one remediation the user can choose.
type Action struct {
	Kind Kind `json:"kind"`
	// Label is the button text — an imperative the user can act on.
	Label string `json:"label"`
	// Detail says exactly what will change, in plain words. A user consenting
	// to something they do not understand has not consented.
	Detail string `json:"detail"`
	// Reversible reports whether Undo can restore the previous state. Shown in
	// the UI so irreversible choices are visibly different.
	Reversible bool `json:"reversible"`
	// Params carry what the executor needs, and what Undo needs afterwards.
	Params map[string]string `json:"params"`
}

// Result records what happened.
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Undo carries the state needed to reverse this action, empty when it
	// cannot be reversed.
	Undo map[string]string `json:"undo,omitempty"`
}

// Executor performs actions. Implementations are platform-specific.
type Executor interface {
	Execute(a Action) Result
	Undo(a Action, undo map[string]string) Result
}

// Suggest proposes the remediations that fit an alert.
//
// Ordering matters: the least destructive effective option comes first, so the
// obvious click is also the safest one. Killing a process is listed before
// quarantining its file because a kill is trivially reversible (start it again)
// while quarantine touches the disk.
func Suggest(area, severity string, ev map[string]any) []Action {
	var out []Action

	image := str(ev, "ImagePath")
	proc := str(ev, "ProcessName")
	pid := str(ev, "PID")
	ip := str(ev, "RemoteIP")
	dest := str(ev, "Destination")

	switch area {
	case "c2":
		if ip != "" {
			out = append(out, Action{
				Kind:       BlockAddress,
				Label:      "Block this connection",
				Detail:     fmt.Sprintf("Adds a Windows Firewall rule stopping all programs on this PC from contacting %s. You can remove it later.", ip),
				Reversible: true,
				Params:     map[string]string{"ip": ip, "dest": dest},
			})
		}
		if pid != "" && pid != "0" && proc != "" {
			out = append(out, Action{
				Kind:       KillProcess,
				Label:      fmt.Sprintf("Stop %s now", proc),
				Detail:     fmt.Sprintf("Closes %s and anything it started. If it is meant to be running, you can open it again.", proc),
				Reversible: false,
				Params:     map[string]string{"pid": pid, "image": image, "name": proc},
			})
		}
		if image != "" && severity == "critical" {
			out = append(out, Action{
				Kind:       QuarantineFile,
				Label:      "Quarantine this program",
				Detail:     fmt.Sprintf("Moves %s somewhere it cannot run and removes permission to execute it. This can be undone.", image),
				Reversible: true,
				Params:     map[string]string{"path": image},
			})
		}

	case "persistence":
		loc, name := str(ev, "Location"), str(ev, "EntryName")
		if loc != "" && name != "" {
			out = append(out, Action{
				Kind:       RemoveAutostart,
				Label:      "Stop this running at startup",
				Detail:     fmt.Sprintf("Removes the %q entry from %s. The program itself is left alone, and this can be undone.", name, loc),
				Reversible: true,
				Params: map[string]string{
					"location": loc, "name": name,
					"target": str(ev, "Target"), "mechanism": str(ev, "Mechanism"),
				},
			})
		}
		if target := str(ev, "TargetPath"); target != "" && severity == "critical" {
			out = append(out, Action{
				Kind:       QuarantineFile,
				Label:      "Quarantine this program",
				Detail:     fmt.Sprintf("Moves %s somewhere it cannot run. This can be undone.", target),
				Reversible: true,
				Params:     map[string]string{"path": target},
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return destructiveness(out[i].Kind) < destructiveness(out[j].Kind)
	})
	return out
}

// destructiveness orders actions from most easily undone to least.
func destructiveness(k Kind) int {
	switch k {
	case BlockAddress:
		return 0 // a firewall rule, deleted in one command
	case RemoveAutostart:
		return 1 // a registry value we recorded and can restore
	case KillProcess:
		return 2 // not reversible, but the user can start it again
	case QuarantineFile:
		return 3 // touches the disk
	}
	return 9
}

func str(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	// Evidence round-trips through JSON in the ledger, so every number returns
	// as float64. Formatting those with %v gives exponent notation above ~1e6
	// ("1.234568e+06"), which taskkill rejects — silently breaking the one
	// button that stops active ransomware on a long-uptime machine.
	switch n := v.(type) {
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case float32:
		return strconv.FormatInt(int64(n), 10)
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case uint32:
		return strconv.FormatUint(uint64(n), 10)
	case uint64:
		return strconv.FormatUint(n, 10)
	}
	s := fmt.Sprintf("%v", v)
	if s == "<nil>" {
		return ""
	}
	return strings.TrimSpace(s)
}

// ValidateUndo checks that an undo record describes a reversal we are willing
// to perform.
//
// SECURITY: undo records are read back from the ledger database and then acted
// on with the agent's (elevated) privileges. If an attacker can write that
// file — and it lives beside the agent, which may be a user-writable folder —
// then unvalidated records are an arbitrary file-move and registry-write
// primitive running as SYSTEM. Structural validation is used rather than
// signing because it needs no secret and survives a database that is restored,
// copied or edited: we simply refuse to reverse anything that does not look
// like something we could have done.
func ValidateUndo(kind Kind, undo map[string]string, quarantineDir string) error {
	switch kind {
	case BlockAddress:
		rule, ip := undo["rule"], undo["ip"]
		if ip == "" || net.ParseIP(ip) == nil {
			return fmt.Errorf("undo record does not name a valid address")
		}
		// The rule name must be one WE generate, so this cannot be used to
		// delete arbitrary firewall rules (a domain-policy rule, say).
		if rule != ruleNameFor(ip) {
			return fmt.Errorf("undo record does not name a NiteWatch firewall rule")
		}
		return nil

	case QuarantineFile:
		from, to := undo["from"], undo["to"]
		if from == "" || to == "" {
			return fmt.Errorf("undo record is incomplete")
		}
		// The source must be inside our own quarantine directory: otherwise
		// this becomes "move any file anywhere", as SYSTEM.
		if !underDir(from, quarantineDir) {
			return fmt.Errorf("refusing to restore from outside the quarantine folder")
		}
		if _, ok := normWin(to); !ok {
			return fmt.Errorf("undo record has an unsafe destination")
		}
		return nil

	case RemoveAutostart:
		switch undo["kind"] {
		case "file":
			if !underDir(undo["from"], quarantineDir) {
				return fmt.Errorf("refusing to restore from outside the quarantine folder")
			}
			return nil
		case "registry":
			// Only autostart locations may be written back, so a tampered
			// record cannot install a service or rewrite an unrelated key.
			if !knownAutostartKey(undo["location"]) {
				return fmt.Errorf("refusing to write outside known startup locations")
			}
			if undo["name"] == "" {
				return fmt.Errorf("undo record has no value name")
			}
			return nil
		}
		return fmt.Errorf("unrecognised undo record")
	}
	return fmt.Errorf("this action cannot be undone")
}

// ruleNameFor must match the executor's naming exactly; it is the check that
// keeps undo from deleting firewall rules we did not create.
func ruleNameFor(ip string) string { return "NiteWatch block " + ip }

// autostartKeyPrefixes are the only registry locations an undo may write.
var autostartKeyPrefixes = []string{
	`hkcu\software\microsoft\windows\currentversion\run`,
	`hklm\software\microsoft\windows\currentversion\run`,
	`hkcu\software\microsoft\windows\currentversion\runonce`,
	`hklm\software\microsoft\windows\currentversion\runonce`,
	`hklm\software\wow6432node\microsoft\windows\currentversion\run`,
	`hklm\software\microsoft\windows nt\currentversion\winlogon`,
	`hklm\software\microsoft\windows nt\currentversion\windows`,
	`hklm\software\microsoft\windows nt\currentversion\image file execution options`,
}

func knownAutostartKey(loc string) bool {
	l := strings.ToLower(strings.TrimSpace(loc))
	for _, p := range autostartKeyPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// underDir reports whether path sits inside dir.
//
// Deliberately does NOT use path/filepath: these are always Windows paths, and
// the checks must behave identically wherever they run — including in tests on
// Linux, where filepath treats a backslash as an ordinary character and would
// silently accept a traversal.
func underDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}
	p, ok := normWin(path)
	if !ok {
		return false // contains traversal
	}
	d, _ := normWin(dir)
	if d == "" {
		return false
	}
	if !strings.HasSuffix(d, `\`) {
		d += `\`
	}
	return strings.HasPrefix(p, d)
}

// normWin lower-cases, collapses separators, and reports whether the path is
// free of ".." components. Rejecting traversal outright is safer than trying to
// resolve it, since the target need not exist yet.
func normWin(p string) (string, bool) {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`))
	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	for _, seg := range strings.Split(p, `\`) {
		if seg == ".." {
			return p, false
		}
	}
	return p, true
}
