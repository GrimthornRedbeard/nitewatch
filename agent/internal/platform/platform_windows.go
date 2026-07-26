//go:build windows

package platform

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// IsElevated reports whether the process is running with an elevated
// (Administrator) token — required for ETW provider subscription.
func IsElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0) // current process token
	member, err := token.IsMember(sid)
	return err == nil && member
}

// OpenBrowser launches the default browser at url.
func OpenBrowser(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// ProcessImage returns the full image path for a running PID, or "" if it can't
// be determined (process exited, or access denied for a protected process).
//
// This covers the case ETW alone cannot: processes that were already running
// when the agent started have no ProcStart event, so their connections would
// otherwise be unattributable.
func ProcessImage(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
