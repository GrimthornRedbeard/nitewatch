package legal

import (
	"strings"
	"testing"
)

// The substance has to survive any future edit to the voice. These are the
// things the notice exists to say; losing one while rewording is the failure
// mode this guards.
func TestPlainNoticeCoversTheSubstance(t *testing.T) {
	low := strings.ToLower(Plain)
	for _, must := range []struct{ what, needle string }{
		{"pre-release status", "pre-release"},
		{"no warranty", "no warranty"},
		{"as-is", "as-is"},
		{"not antivirus", "not antivirus"},
		{"keep Defender on", "defender"},
		{"can be wrong both ways", "wrong in both directions"},
		{"remediation is the user's choice", "yours to press"},
		{"risk is the user's", "at your own risk"},
		{"a way to get in touch", "threattape@gmail.com"},
	} {
		if !strings.Contains(low, strings.ToLower(must.needle)) {
			t.Errorf("the notice no longer states %s (looked for %q)", must.what, must.needle)
		}
	}
}

// The formal wording is what a court would look for. It is kept alongside the
// readable version, not instead of it, and neither may quietly lose the other's
// content.
func TestFormalTermsCarryTheStandardLanguage(t *testing.T) {
	for _, needle := range []string{
		`"AS IS"`, "WITHOUT WARRANTY OF ANY KIND", "MERCHANTABILITY",
		"FITNESS FOR A PARTICULAR PURPOSE", "IN NO EVENT SHALL",
		"CONSEQUENTIAL DAMAGES", "YOU ASSUME ALL RISK", "THREAT TAPE LLC",
		"threattape@gmail.com",
	} {
		if !strings.Contains(Formal, needle) {
			t.Errorf("formal terms missing %q", needle)
		}
	}
}

// Acceptance is recorded against the version, so the version must actually
// change when the words do — otherwise somebody's consent to the old terms
// silently covers new ones.
func TestVersionTracksTheText(t *testing.T) {
	before := Version()
	if len(before) != 16 {
		t.Errorf("version = %q, want 16 hex chars", before)
	}
	if Version() != before {
		t.Error("version must be stable for identical text")
	}
	// A single character of difference in any field must change the version,
	// or consent to the old wording silently covers the new.
	base := versionOf("h", "p", "f")
	for _, v := range []string{
		versionOf("H", "p", "f"),
		versionOf("h", "p.", "f"),
		versionOf("h", "p", "f "),
	} {
		if v == base {
			t.Error("version did not change when the text did")
		}
	}
	// And the separator must stop fields running together: these differ only in
	// where the boundary falls.
	if versionOf("ab", "c", "d") == versionOf("a", "bc", "d") {
		t.Error("field boundaries are not part of the hash")
	}
}

// The startup line has to stand alone: plenty of people will never open the
// dashboard.
func TestLogTextStandsAlone(t *testing.T) {
	low := strings.ToLower(LogText)
	for _, needle := range []string{"pre-release", "no warranty", "own risk", "defender", "threattape@gmail.com"} {
		if !strings.Contains(low, needle) {
			t.Errorf("startup notice missing %q", needle)
		}
	}
}
