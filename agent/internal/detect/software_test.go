// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import "testing"

const msDefender = `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe`

// Every case below is an alert a real three-day soak actually produced.

func TestDefenderScanningIsNotCredentialTheft(t *testing.T) {
	// The exact alert: "MsMpEng.exe is reading your Firefox cookies, which can
	// be used to sign in as you." It was Defender running a scan.
	got := detectCredentialTheft(FileSubject{
		Image:  msDefender,
		Path:   `C:\Users\k\AppData\Roaming\Mozilla\Firefox\Profiles\7t5.default-release\cookies.sqlite`,
		Signed: true, Signer: "Microsoft Windows Publisher",
	})
	if got != nil {
		t.Errorf("Defender scanning a cookie store still alerts: %v", got)
	}
}

// The old exclusion was a C:\Windows\ prefix test. Defender moved out of
// System32 years ago so its engine could update independently of the OS, which
// is why that test silently stopped covering it.
func TestDefenderIsNotUnderWindowsAnyMore(t *testing.T) {
	if pathIsUnderWindows(msDefender) {
		t.Fatal("test premise is wrong; the old prefix check would have caught this")
	}
	if !SecurityScanner(msDefender, true, "Microsoft Windows Publisher") {
		t.Error("Defender's real install path is not recognised as a scanner")
	}
}

// The suppression must not be claimable by name alone, or it becomes the
// easiest bypass in the product: rename yourself MsMpEng.exe, read everything.
func TestAnUnsignedImpostorGetsNoScannerPass(t *testing.T) {
	for _, c := range []struct {
		name   string
		signed bool
		signer string
	}{
		{"unsigned", false, ""},
		{"signed by somebody else", true, "Definitely Legitimate Software Ltd"},
	} {
		if SecurityScanner(`C:\Users\k\Downloads\MsMpEng.exe`, c.signed, c.signer) {
			t.Errorf("%s: an impostor was treated as anti-malware", c.name)
		}
		got := detectCredentialTheft(FileSubject{
			Image:  `C:\Users\k\Downloads\MsMpEng.exe`,
			Path:   `C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
			Signed: c.signed, Signer: c.signer,
		})
		if got == nil {
			t.Errorf("%s: an impostor reading Chrome's password store was suppressed", c.name)
		}
	}
}

// "brave.exe is reading your saved Edge passwords" — which is Brave's import
// feature sweeping Edge's profile, as every Chromium browser offers to do.
func TestBrowserImportIsNotTheft(t *testing.T) {
	got := detectCredentialTheft(FileSubject{
		Image:  `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
		Path:   `C:\Users\k\AppData\Local\Microsoft\Edge\User Data\Default\Login Data`,
		Signed: true, Signer: "Brave Software, Inc.",
	})
	if got != nil {
		t.Errorf("a browser importing from another browser still alerts: %v", got)
	}
}

// The import pass is narrow on purpose. A non-browser reading a browser's
// password store is the original alert and must survive, however it is signed.
func TestOnlyBrowsersGetTheImportPass(t *testing.T) {
	cases := []struct {
		name   string
		image  string
		signed bool
		signer string
	}{
		{"an Electron app", `C:\Program Files\WindowsApps\Claude\app\claude.exe`, true, "Anthropic PBC"},
		{"an unsigned program calling itself a browser", `C:\Users\k\Temp\brave.exe`, false, ""},
		{"a browser signed by an unrecognised publisher", `C:\Users\k\AppData\Local\Fake\brave.exe`, true, "Totally Real Browsers Ltd"},
	}
	for _, c := range cases {
		path := `C:\Users\k\AppData\Local\Microsoft\Edge\User Data\Default\Login Data`
		if got := detectCredentialTheft(FileSubject{
			Image: c.image, Path: path, Signed: c.signed, Signer: c.signer,
		}); got == nil {
			t.Errorf("%s: suppressed, but this is the alert the rule exists for", c.name)
		}
	}
}

// A browser reading its OWN store was already handled by the owner check, and
// must stay handled.
func TestBrowserReadingItsOwnStoreIsSilent(t *testing.T) {
	if got := detectCredentialTheft(FileSubject{
		Image:  `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		Path:   `C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
		Signed: true, Signer: "Google LLC",
	}); got != nil {
		t.Errorf("chrome reading its own passwords alerts: %v", got)
	}
}

func TestBrowserPredicateNeedsASignature(t *testing.T) {
	if Browser(`C:\Users\k\Downloads\chrome.exe`, false, "") {
		t.Error("an unsigned chrome.exe was treated as a browser")
	}
	if !Browser(`C:\Program Files\Google\Chrome\Application\chrome.exe`, true, "Google LLC") {
		t.Error("a signed Chrome was not recognised")
	}
}
