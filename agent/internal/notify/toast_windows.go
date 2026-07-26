//go:build windows

package notify

import (
	"fmt"
	"os/exec"
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

func (t *WindowsToast) Notify(a Alert) error {
	title := a.Title
	if a.Severity == "critical" {
		title = "⚠ " + title
	}
	body := a.Body
	if body == "" {
		body = "Open NiteWatch to see what happened and what to do."
	}

	script := fmt.Sprintf(`
$ErrorActionPreference='Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$t = $xml.GetElementsByTagName('text')
$t.Item(0).AppendChild($xml.CreateTextNode(%s)) > $null
$t.Item(1).AppendChild($xml.CreateTextNode(%s)) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(%s).Show($toast)
`, quotePS(title), quotePS(truncate(body, 220)), quotePS(t.AppID))

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("toast failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// truncate keeps a toast readable; Windows silently clips long text anyway, and
// the dashboard carries the full narrative.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func quotePS(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
