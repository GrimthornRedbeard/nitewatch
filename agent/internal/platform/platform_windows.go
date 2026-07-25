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
