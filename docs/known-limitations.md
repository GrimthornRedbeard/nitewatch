# Known Limitations — moved

The canonical file now lives at:

    agent/internal/help/known-limitations.md

It moved so it could be compiled into the binary with `go:embed` and read from
the dashboard, under **Known limitations** in the header. A user running the exe
has no repository to look in, and the startup disclaimer points them at this
document — so it has to travel with the build.

`go:embed` cannot reach outside its module, and the Go module root is `agent/`,
which put `docs/` out of reach. The alternative was copying the file into the
module at build time; the rule packs already taught us what that costs — see the
package comment in `agent/rules/embed.go`, where a duplicate silently went stale
and the agent shipped with one rule pack while the tests exercised four.

One copy, one truth.
