// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package api

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writePrivateFile creates path exclusively with a protected DACL admitting
// only SYSTEM and Administrators.
//
// On Windows, Go's file mode bits do not become an ACL: os.WriteFile(…, 0600)
// only decides the read-only attribute, and the file inherits its folder's
// permissions — which, beside a portable exe, usually include the signed-in
// user. The DACL is supplied to CreateFile itself, so there is no moment at
// which the file exists with the inherited ACL.
//
// The owner is set to Administrators too, when the agent is elevated. If the
// owner were the user's own SID, the user would hold implicit WRITE_DAC and
// could grant themselves read access. When the agent is not elevated, setting
// that owner fails and the file is created without it: the agent then has no
// more rights than the user, so there is nothing to protect from them.
func writePrivateFile(path string, data []byte) error {
	h, err := createWithSDDL(path, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		h, err = createWithSDDL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func createWithSDDL(path, sddl string) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, windows.GENERIC_WRITE, 0, &sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
}
