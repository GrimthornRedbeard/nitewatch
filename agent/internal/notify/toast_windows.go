// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package notify

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WindowsToast shows native Windows notifications.
//
// Uses the WinRT toast API through PowerShell rather than binding it directly:
// toasts fire rarely, and a shipped binary that crashes in a COM call is a far
// worse outcome than a notification that takes 300ms to appear.
type WindowsToast struct {
	// AppID identifies the sender. PowerShell's is used because a toast from an
	// unregistered AppID is silently dropped on many builds — registering our
	// own requires a Start Menu shortcut, which belongs with the installer.
	AppID string
}

func NewWindowsToast() *WindowsToast {
	return &WindowsToast{AppID: `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`}
}

// toastScript reads its text from the ENVIRONMENT rather than having it
// interpolated into the script body.
//
// SECURITY: alert titles and bodies contain attacker-controlled strings —
// process names and file paths, straight from disk. PowerShell's tokenizer
// accepts U+2018, U+2019, U+201A and U+201B as string delimiters in addition to
// U+0027, so escaping quotes cannot make interpolation safe: a filename holding
// a Unicode right-quote closes the literal and the rest executes. This process
// runs elevated, so that was a route from "name a file cleverly" to SYSTEM code
// execution. Environment variables are read as data by $env: and never parsed
// as code, which removes the bug class instead of patching one character.
const toastScript = `$ErrorActionPreference='Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$t = $xml.GetElementsByTagName('text')
$t.Item(0).AppendChild($xml.CreateTextNode($env:NW_TOAST_TITLE)) > $null
$t.Item(1).AppendChild($xml.CreateTextNode($env:NW_TOAST_BODY)) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:NW_TOAST_APPID).Show($toast)`

func (t *WindowsToast) Notify(a Alert) error {
	title := truncate(a.Title, 120)
	if a.Severity == "critical" {
		title = "\u26a0 " + title
	}
	body := a.Body
	if body == "" {
		body = "Open NiteWatch to see what happened and what to do."
	}

	cmd := exec.Command(system32("WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", toastScript)
	cmd.Env = append(os.Environ(),
		"NW_TOAST_TITLE="+title,
		"NW_TOAST_BODY="+truncate(body, 220),
		"NW_TOAST_APPID="+t.AppID,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("toast failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// truncate keeps a toast readable and bounds the command line. It operates on
// RUNES: byte-slicing UTF-8 can split a character and emit invalid text.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// system32 builds an absolute path under the real system directory. An elevated
// process must not resolve helper binaries through %PATH%: a user-writable
// directory on the path — which third-party installers add routinely — would
// let an unprivileged user plant powershell.exe and have us run it as SYSTEM.
func system32(parts ...string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(append([]string{root, "System32"}, parts...)...)
}
