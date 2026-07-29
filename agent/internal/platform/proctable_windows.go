// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package platform

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcInfo is one entry from the live process table.
type ProcInfo struct {
	PID   uint32
	PPID  uint32
	Image string
	// Services lists the Windows services hosted in this process. For
	// svchost.exe this is the ONLY useful identity: every copy is spawned by
	// services.exe from the same binary, so "svchost.exe" tells a user nothing
	// while "Windows Update" tells them everything.
	Services []string
}

// ProcessTable snapshots every running process with its parent.
//
// This exists because an agent starting on a running machine has no history:
// svchost, explorer, the browser and every service began long before it, so
// their ProcessStart events were never observed and the causal graph has no
// lineage for them. Seeding the graph from a snapshot is what lets the UI
// answer "what started this?" for processes the agent never saw begin.
func ProcessTable() ([]ProcInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	svc := servicesByPID()

	var out []ProcInfo
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))

	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		name := windows.UTF16ToString(e.ExeFile[:])
		info := ProcInfo{PID: e.ProcessID, PPID: e.ParentProcessID, Image: name, Services: svc[e.ProcessID]}
		// Prefer the full path where we can read it; the snapshot gives only
		// the base name, and a bare "svchost.exe" cannot be told apart from a
		// copy dropped somewhere it should not be.
		if full := ProcessImage(e.ProcessID); full != "" {
			info.Image = full
		}
		out = append(out, info)
	}
	return out, nil
}

var (
	svcMu      sync.Mutex
	svcCache   map[uint32][]string
	svcFetched time.Time
)

// servicesByPID maps process IDs to the services running inside them, cached
// briefly because enumerating the SCM is not free and service hosting is stable.
func servicesByPID() map[uint32][]string {
	svcMu.Lock()
	defer svcMu.Unlock()
	if svcCache != nil && time.Since(svcFetched) < 60*time.Second {
		return svcCache
	}

	out := map[uint32][]string{}
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		svcCache, svcFetched = out, time.Now()
		return out
	}
	defer windows.CloseServiceHandle(m)

	var needed, returned, resume uint32
	// First call sizes the buffer.
	err = windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
		nil, 0, &needed, &returned, &resume, nil)
	if needed == 0 {
		svcCache, svcFetched = out, time.Now()
		return out
	}

	buf := make([]byte, needed)
	resume = 0
	if err = windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
		&buf[0], uint32(len(buf)), &needed, &returned, &resume, nil); err != nil {
		svcCache, svcFetched = out, time.Now()
		return out
	}

	type enumServiceStatusProcess struct {
		ServiceName   *uint16
		DisplayName   *uint16
		ServiceStatus windows.SERVICE_STATUS_PROCESS
	}
	entries := unsafe.Slice((*enumServiceStatusProcess)(unsafe.Pointer(&buf[0])), int(returned))
	for _, s := range entries {
		pid := s.ServiceStatus.ProcessId
		if pid == 0 {
			continue // not running
		}
		// The display name is what a person recognises ("Windows Update"),
		// which is the entire point of resolving this.
		name := windows.UTF16PtrToString(s.DisplayName)
		if name == "" {
			name = windows.UTF16PtrToString(s.ServiceName)
		}
		if name != "" {
			out[pid] = append(out[pid], name)
		}
	}

	svcCache, svcFetched = out, time.Now()
	return out
}

// ServiceLabel renders a process for display, naming the services it hosts.
// "svchost.exe" becomes "Windows Update (svchost.exe)".
func ServiceLabel(image string, services []string) string {
	if len(services) == 0 {
		return image
	}
	base := image
	if i := strings.LastIndexAny(image, `\/`); i >= 0 {
		base = image[i+1:]
	}
	shown := services
	if len(shown) > 3 {
		shown = append(append([]string{}, shown[:3]...), "…")
	}
	return strings.Join(shown, ", ") + " (" + base + ")"
}
