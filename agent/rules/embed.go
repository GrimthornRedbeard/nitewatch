// Package rulesdata embeds the shipped detection rule packs.
//
// The packs live here, beside the YAML, and are embedded from this package
// rather than copied somewhere the binary can reach. An earlier version kept a
// duplicate under cmd/ so go:embed could find it; that copy silently went
// stale, and the agent shipped with one rule pack while the tests exercised
// four. One copy, one truth.
package rulesdata

import "embed"

// Packs holds every shipped rule pack.
var (
	//go:embed *.yaml
	Packs embed.FS
)
