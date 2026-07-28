package filewatch

import "testing"

// Reported from a live machine:
//
//	ALERT [critical] Dell.TechHub.Instrumentation.UserProcess.exe is reading
//	your Firefox profile, which stores saved passwords
//
// The rule matched the whole Firefox profile directory, so touching a
// bookmark, a preference or a cached favicon was reported as credential theft.
// Every other browser in the list matches one specific file.
func TestFirefoxMatchesCredentialFilesNotTheWholeProfile(t *testing.T) {
	const prof = `C:\Users\k\AppData\Roaming\Mozilla\Firefox\Profiles\a1b2c3.default-release\`

	// Ordinary profile contents: not credentials, must not fire.
	for _, f := range []string{
		"prefs.js", "places.sqlite", "favicons.sqlite", "sessionstore.jsonlz4",
		"extensions.json", "addonStartup.json.lz4", "handlers.json",
		`storage\default\moz-extension+++abc\idb\1234.sqlite`,
	} {
		if what, _ := CredentialInfo(prof + f); what != "" {
			t.Errorf("%s should not be treated as a credential store, got %q", f, what)
		}
	}

	// The files that actually hold passwords, or the key to them.
	for _, f := range []string{"logins.json", "key4.db", "key3.db", "signons.sqlite"} {
		what, owner := CredentialInfo(prof + f)
		if what == "" {
			t.Errorf("%s should be recognised as a credential store", f)
		}
		if owner != "firefox.exe" {
			t.Errorf("%s: owner = %q, want firefox.exe", f, owner)
		}
	}
	if what, _ := CredentialInfo(prof + "cookies.sqlite"); what == "" {
		t.Error("cookies.sqlite should be recognised — session theft is the same problem")
	}
}

// The filenames are not unique enough on their own; a match must also be inside
// a Firefox profile.
func TestFirefoxFilenamesDoNotMatchElsewhere(t *testing.T) {
	for _, p := range []string{
		`C:\Users\k\Projects\myapp\logins.json`,
		`C:\Users\k\Downloads\cookies.sqlite`,
		`C:\Program Files\SomeApp\key4.db`,
	} {
		if what, _ := CredentialInfo(p); what != "" {
			t.Errorf("%s matched as %q — the path check is not being applied", p, what)
		}
	}
}

// The other browsers were already specific; keep them that way.
func TestOtherBrowsersStillMatchTheirCredentialFiles(t *testing.T) {
	cases := map[string]string{
		`C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`:               "chrome.exe",
		`C:\Users\k\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data`: "brave.exe",
		`C:\Users\k\AppData\Local\Microsoft\Edge\User Data\Default\Login Data`:              "msedge.exe",
	}
	for path, owner := range cases {
		what, got := CredentialInfo(path)
		if what == "" || got != owner {
			t.Errorf("%s -> what=%q owner=%q, want owner %q", path, what, got, owner)
		}
	}
	// And a Chrome bookmark file is not a credential store.
	if what, _ := CredentialInfo(`C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Bookmarks`); what != "" {
		t.Errorf("Chrome Bookmarks matched as %q", what)
	}
}
