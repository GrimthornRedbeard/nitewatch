package detect

import "strings"

// SignerMatchesOrg reports whether the program's publisher is also the operator
// of the network it is talking to — Anthropic-signed software reaching a network
// registered to ANTHROPIC, Valve-signed software reaching VALVE-CORPORATION.
//
// This is the pairing that separates "a desktop app polling its own backend"
// from "a signed binary checking in with somebody else's server." Signing alone
// is not enough to excuse a rhythm: certificates get stolen and abused, and a
// signed implant beaconing to unrelated hosting is exactly what the detector
// exists to catch. Signing plus ownership is a different claim — the publisher
// is talking to itself, in the open, over infrastructure registered in its own
// name.
//
// Matching is on the significant word of each, because publishers and registries
// spell the same company differently: "Anthropic PBC" against "ANTHROPIC",
// "Valve Corp." against "VALVE-CORPORATION". Corporate suffixes are dropped
// since they carry no identity and would otherwise match every company against
// every other.
//
// Used only to suppress, never to accuse. A false match costs sensitivity on one
// program/destination pair; it never grants trust to anything.
func SignerMatchesOrg(signer, org string) bool {
	sig := significantWords(signer)
	o := significantWords(org)
	if len(sig) == 0 || len(o) == 0 {
		return false
	}
	for _, a := range sig {
		for _, b := range o {
			// Whole-word equality, or one containing the other, which covers
			// "brave" vs "bravesoftware" and "valve" vs "valvecorporation".
			if a == b || (len(a) >= 4 && strings.Contains(b, a)) || (len(b) >= 4 && strings.Contains(a, b)) {
				return true
			}
		}
	}
	return false
}

// corporateSuffix lists the words that identify a legal form rather than a
// company. Without dropping these, "Example Inc" and "Attacker Inc" match.
var corporateSuffix = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true,
	"corporation": true, "company": true, "co": true, "pbc": true, "plc": true,
	"gmbh": true, "ag": true, "ab": true, "as": true, "sa": true, "sas": true,
	"bv": true, "nv": true, "oy": true, "pty": true, "srl": true, "spa": true,
	"holdings": true, "group": true, "technologies": true, "technology": true,
	"software": true, "systems": true, "solutions": true, "services": true,
	"labs": true, "studio": true, "studios": true, "digital": true,
	"international": true, "global": true, "network": true, "networks": true,
	"communications": true, "telecom": true, "hosting": true, "internet": true,
	"the": true, "and": true, "of": true,
}

// significantWords reduces a publisher or AS-org string to comparable identity
// words: lowercase letters only, split on anything else, corporate forms and
// very short fragments removed.
func significantWords(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		w := cur.String()
		cur.Reset()
		if len(w) < 3 || corporateSuffix[w] {
			return
		}
		out = append(out, w)
	}
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}
