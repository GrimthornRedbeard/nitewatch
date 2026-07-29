// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import (
	"strings"
)

// InstallTrust describes what a program's location tells us about how it got
// onto the machine.
//
// This exists because "is it signed?" turned out to be the wrong question on
// modern Windows. Microsoft Store apps are packaged as MSIX and signed at the
// PACKAGE level; `Get-AuthenticodeSignature` on the .exe inside frequently
// reports NotSigned because there is no embedded Authenticode signature to
// find. The program is signed, vetted and installed by Microsoft — and the
// agent was calling it "software with no publisher" and raising an alert every
// time one contacted its own service.
//
// Location is a real, independent trust signal, not a workaround: it says who
// was able to put the file there.
type InstallTrust struct {
	// Vouched reports that something accountable put this program here — a
	// signature we verified, or an install location only a privileged
	// installer can write to.
	Vouched bool
	// Why is a plain-English reason, shown to the user rather than logged.
	Why string
	// Store is true for Microsoft Store / MSIX packages.
	Store bool
}

// storeRoots are directories only the AppX deployment service can write to.
//
// WindowsApps is owned by TrustedInstaller with an ACL that denies write even
// to administrators without taking ownership first. A file being there means it
// arrived through the Store pipeline, which signs and vets every package. That
// is a stronger statement than an Authenticode signature, which anyone with
// $200 and a company name can obtain.
var storeRoots = []string{
	`\program files\windowsapps\`,
	`\program files (x86)\windowsapps\`,
	`\windows\systemapps\`,
}

// NOTE: System32 is deliberately NOT on any trust list. It is writable by
// administrators, and dropping a binary there is a standard malware move — so
// location proves nothing about it. It also does not need an exemption:
// Windows' own components carry catalog signatures that the signature check
// reads correctly. WindowsApps is different on both counts, which is the whole
// reason this file exists.

// ClassifyInstall reports what the location of a program implies, given
// whatever the signature check managed to determine.
func ClassifyInstall(image string, signed bool, signer string) InstallTrust {
	if image == "" {
		return InstallTrust{}
	}
	p := strings.ToLower(strings.ReplaceAll(image, "/", `\`))

	for _, root := range storeRoots {
		if strings.Contains(p, root) {
			return InstallTrust{
				Vouched: true, Store: true,
				Why: "installed from the Microsoft Store, which signs and checks every app " +
					"before publishing it. Only Windows itself can write to that folder.",
			}
		}
	}
	if signed {
		why := "digitally signed, so Windows can confirm who published it"
		if signer != "" {
			why += " — " + signer
		}
		return InstallTrust{Vouched: true, Why: why + "."}
	}
	return InstallTrust{}
}

// PublisherVouched is the question the detectors actually want to ask: is there
// anything accountable behind this program? Replaces bare `Signed` checks,
// which answered a narrower question than the rules assumed.
func PublisherVouched(image string, signed bool, signer string) bool {
	return ClassifyInstall(image, signed, signer).Vouched
}

// StorePackage pulls the readable package identity out of a WindowsApps path.
//
// The folder name carries it: "5319275A.WhatsAppDesktop_2.2627.101.0_x64__cv1g1gvanyjgm"
// is publisher-prefix, product, version, architecture, and the publisher hash
// that Windows derives from the signing certificate. That last part is the
// useful bit for somebody checking a program is what it claims: two packages
// from the same publisher share it, and it cannot be forged without the
// certificate.
func StorePackage(image string) (name, version, publisherID string, ok bool) {
	p := strings.ReplaceAll(image, "/", `\`)
	low := strings.ToLower(p)
	var idx int
	var found bool
	for _, root := range storeRoots {
		if i := strings.Index(low, root); i >= 0 {
			idx = i + len(root)
			found = true
			break
		}
	}
	if !found || idx >= len(p) {
		return "", "", "", false
	}
	rest := p[idx:]
	if i := strings.IndexByte(rest, '\\'); i >= 0 {
		rest = rest[:i]
	}
	// <publisher>.<Product>_<version>_<arch>__<publisherHash>
	if i := strings.Index(rest, "__"); i >= 0 {
		publisherID = rest[i+2:]
		rest = rest[:i]
	}
	parts := strings.Split(rest, "_")
	name = parts[0]
	if len(parts) > 1 {
		version = parts[1]
	}
	return name, version, publisherID, name != ""
}

// SystemProcess reports whether an image refers to the Windows kernel rather
// than to a program somebody installed.
//
// PID 4 is the System process, and ETW attributes a great deal of file I/O to
// it that no program asked for: the cache manager writing back memory-mapped
// pages, prefetch, defragmentation. That is how "System is reading your saved
// Edge passwords" happens — Edge dirtied a page and Windows flushed it later,
// in the kernel's context.
//
// It also cannot be acted on. There is no file to quarantine, and terminating
// PID 4 stops the computer. Offering either is worse than saying nothing.
func SystemProcess(image string) bool {
	switch strings.ToLower(strings.TrimSpace(image)) {
	case "system", "system idle process", "registry", "memory compression", "":
		return true
	}
	return false
}

// ActionableImage reports whether an image is a real file path that a
// remediation could act on. "System" is a name, not a path; so is a bare
// executable name recovered without its directory.
func ActionableImage(image string) bool {
	if SystemProcess(image) {
		return false
	}
	return strings.ContainsAny(image, `\/`)
}
