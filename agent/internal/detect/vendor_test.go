// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import "testing"

// The pairing that matters: publisher and network operator are the same
// company, spelled differently by a certificate and a routing registry.
func TestSignerMatchesOrgOnRealPairings(t *testing.T) {
	yes := [][2]string{
		{"Anthropic PBC", "ANTHROPIC"},
		{"Anthropic, PBC", "ANTHROPIC-AS"},
		{"Valve Corp.", "VALVE-CORPORATION"},
		{"Microsoft Corporation", "MICROSOFT-CORP-MSN-AS-BLOCK"},
		{"Brave Software, Inc.", "BRAVESOFTWARE"},
		{"Spotify AB", "SPOTIFY-AS"},
		{"Discord Inc.", "DISCORD"},
	}
	for _, c := range yes {
		if !SignerMatchesOrg(c[0], c[1]) {
			t.Errorf("SignerMatchesOrg(%q, %q) = false, want true", c[0], c[1])
		}
	}
}

// A signed binary checking in with somebody else's server is exactly what the
// beacon detector exists to catch. Certificates get stolen; signing alone must
// never excuse a rhythm.
func TestSignerMatchesOrgRejectsUnrelatedOperators(t *testing.T) {
	no := [][2]string{
		{"Anthropic PBC", "SOME-SMALL-HOSTING-LLC"},
		{"Anthropic PBC", "HOSTKEY-AS"},
		{"Valve Corp.", "ANTHROPIC"},
		{"", "ANTHROPIC"},     // unsigned, or signer unknown
		{"Anthropic PBC", ""}, // no ownership data loaded
		{"", ""},
		// Corporate suffixes carry no identity and must not match on their own.
		{"Example Inc", "Attacker Inc"},
		{"Widget Technologies Ltd", "Malware Technologies Ltd"},
		{"Acme Software", "Evil Software"},
	}
	for _, c := range no {
		if SignerMatchesOrg(c[0], c[1]) {
			t.Errorf("SignerMatchesOrg(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

func TestSignificantWordsDropsNoise(t *testing.T) {
	got := significantWords("Brave Software, Inc.")
	if len(got) != 1 || got[0] != "brave" {
		t.Errorf("significantWords = %v, want [brave]", got)
	}
	if w := significantWords("LLC Inc Ltd"); len(w) != 0 {
		t.Errorf("a string of only corporate forms should yield nothing, got %v", w)
	}
}
