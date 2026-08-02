// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import "strings"

// This file knows about two kinds of program that break the ordinary rules,
// both identified by a three-day soak on a real desktop that produced five
// alerts, every one of them wrong in one of these two ways.
//
// Neither predicate trusts a filename on its own. "Is this program called
// MsMpEng.exe" is a question any piece of malware can answer however it likes,
// so both require a valid signature from a publisher we already trust before
// the name is allowed to mean anything.

// securityScanners are the images of anti-malware engines that read every file
// on the machine as their entire purpose.
//
// Windows Defender is the one that matters and the one that caught us out. The
// credential detector skipped anything under C:\Windows\, on the reasoning that
// Windows' own components legitimately touch these files — but Defender has not
// lived in System32 for years. It runs from
// C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\MsMpEng.exe so
// that its engine can update independently of the OS. The exclusion was written
// against a layout Microsoft had already abandoned, which is why a soak
// reported "MsMpEng.exe is reading your Firefox cookies" as a critical
// information-stealer alert. It was Defender doing a scan.
var securityScanners = map[string]bool{
	"msmpeng.exe":       true, // Microsoft Defender engine
	"mssense.exe":       true, // Defender for Endpoint sensor
	"nissrv.exe":        true, // Defender network inspection
	"windefend.exe":     true,
	"sensecncproxy.exe": true,
	// Third-party engines behave identically: they read everything, including
	// every credential store, because that is how scanning works.
	"avp.exe":               true, // Kaspersky
	"avastsvc.exe":          true,
	"avgsvc.exe":            true,
	"mbamservice.exe":       true, // Malwarebytes
	"mbam.exe":              true,
	"ekrn.exe":              true, // ESET
	"bdagent.exe":           true, // Bitdefender
	"vsserv.exe":            true, // Bitdefender
	"ccsvchst.exe":          true, // Norton
	"mcshield.exe":          true, // McAfee
	"sophosfilescanner.exe": true,
	"savservice.exe":        true, // Sophos
	"cb.exe":                true, // Carbon Black
	"csfalconservice.exe":   true, // CrowdStrike
	"sentinelagent.exe":     true, // SentinelOne
}

// SecurityScanner reports whether an image is anti-malware doing its job.
//
// Requires a signature from a trusted publisher. A file called MsMpEng.exe in
// a user's Downloads folder is not Defender, and this must not become the
// easiest suppression in the product to abuse.
func SecurityScanner(image string, signed bool, signer string) bool {
	if !signed || !TrustedSigner(signer) {
		return false
	}
	return securityScanners[strings.ToLower(shortName(image))]
}

// browsers are the images that browse the web on a person's behalf.
var browsers = map[string]bool{
	"chrome.exe":    true,
	"msedge.exe":    true,
	"firefox.exe":   true,
	"brave.exe":     true,
	"opera.exe":     true,
	"vivaldi.exe":   true,
	"iexplore.exe":  true,
	"librewolf.exe": true,
	"chromium.exe":  true,
	"waterfox.exe":  true,
	"tor.exe":       true,
	"arc.exe":       true,
}

// Browser reports whether an image is a signed, recognised web browser.
//
// Used for two suppressions that look unrelated and share a cause — a browser
// is a *user agent*, and things that would be damning from an ordinary program
// are the defining behaviour of one.
func Browser(image string, signed bool, signer string) bool {
	if !signed || !TrustedSigner(signer) {
		return false
	}
	return browsers[strings.ToLower(shortName(image))]
}

// BrowserImport reports that one browser is reading another browser's
// credential store — which is the import feature, not theft.
//
// Every Chromium-derived browser offers to bring your passwords and bookmarks
// across on first run, and several re-check for importable profiles afterwards.
// A soak caught "brave.exe is reading your saved Edge passwords" and it was
// exactly that: Brave sweeping Edge's User Data directory.
//
// The reader must be a signed, recognised browser and the file must belong to a
// DIFFERENT recognised browser. An unsigned program reading Edge's Login Data
// is still the alert it always was, whatever it calls itself.
func BrowserImport(readerImage string, signed bool, signer, ownerImage string) bool {
	if ownerImage == "" || !Browser(readerImage, signed, signer) {
		return false
	}
	owner := strings.ToLower(shortName(ownerImage))
	if !browsers[owner] {
		return false
	}
	return owner != strings.ToLower(shortName(readerImage))
}
