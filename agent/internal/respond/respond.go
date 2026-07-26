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
	"sort"
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
	s := fmt.Sprintf("%v", v)
	if s == "<nil>" {
		return ""
	}
	return strings.TrimSpace(s)
}
