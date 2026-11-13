// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package seal

import (
	"crypto/rand"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The key lives in HKLM rather than in a file beside the exe because the
// folder beside the exe is usually writable by the user. A file there could be
// deleted and replaced with one whose contents the attacker chose; a subkey of
// HKLM\SOFTWARE can only be created by an administrator, so nothing
// unprivileged can plant it in advance.
const (
	keyPath   = `SOFTWARE\NiteWatch`
	valueName = "RecordSealKey"

	// SYSTEM and Administrators only, not inherited from HKLM\SOFTWARE (whose
	// ACL lets every user read). Under UAC the signed-in user's unelevated
	// token carries Administrators as deny-only, so it cannot open the key.
	keySDDL = "O:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)"
)

var procRegCreateKeyExW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegCreateKeyExW")

// Persistent loads the sealing key, creating it on first run.
//
// The key is created WITH its protective DACL in a single RegCreateKeyEx call.
// Creating it first and tightening the ACL afterwards would leave a window in
// which any user could open a read handle and keep it.
//
// Fails when the agent is not elevated; the caller then falls back to an
// Ephemeral key.
func Persistent() (*Key, string, error) {
	sd, err := windows.SecurityDescriptorFromString(keySDDL)
	if err != nil {
		return nil, "", err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))

	sub, err := windows.UTF16PtrFromString(keyPath)
	if err != nil {
		return nil, "", err
	}
	var h windows.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyExW.Call(
		uintptr(windows.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(sub)),
		0, 0,
		0, // REG_OPTION_NON_VOLATILE
		uintptr(registry.QUERY_VALUE|registry.SET_VALUE),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r != 0 {
		return nil, "", fmt.Errorf("create HKLM\\%s: %w", keyPath, windows.Errno(r))
	}
	k := registry.Key(h)
	defer k.Close()

	where := `HKLM\` + keyPath
	if b, _, err := k.GetBinaryValue(valueName); err == nil && len(b) == KeySize {
		key, err := New(b)
		return key, where, err
	}

	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, "", err
	}
	if err := k.SetBinaryValue(valueName, b); err != nil {
		return nil, "", fmt.Errorf("store sealing key: %w", err)
	}
	key, err := New(b)
	return key, where, err
}
