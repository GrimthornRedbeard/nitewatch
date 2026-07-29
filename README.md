# NiteWatch

**Somebody's knocking on your door at 3am. Here's who.**

NiteWatch is a lightweight personal security agent for Windows. It watches what
your computer is actually doing — which programs are running, who they're
talking to, what files they're touching — and when something is wrong, it tells
you the story in plain English with a one-click fix.

- **Who's talking?** A permanent, process-attributed log of every outbound
  connection: which program, which server, which domain, when — plus who owns
  the address block and what country it's registered in.
- **The whole story.** Click any connection to see the causal chain that
  produced it: *program started → looked up a name → connected*. Reconstructed
  from a causal event graph, ordered by logical clock rather than wall time.
- **Do this.** Alerts come with plain-English explanations and one-click
  remediation — block, stop, quarantine, remove from startup — each with undo
  where the change can be reversed.
- **Private by design.** Everything is analysed on your machine. Threat
  intelligence and address-ownership data are pulled *down*; nothing about your
  traffic goes *up*.

## What it detects

| Area | Examples |
|---|---|
| **Command & control** | connections to known malware infrastructure, programs dialling bare addresses they never looked up, unsigned software reaching new destinations, first contact with watched jurisdictions |
| **Persistence** | autostart entries added from temporary folders, an existing startup entry silently repointed, launch hijacking (IFEO/AppInit) |
| **Ransomware** | one program rewriting many documents across folders, encryption-style renames, ransom notes, backup destruction |
| **Credential theft** | a program that isn't the owner reading saved passwords, SSH keys, cloud credentials or wallet files |

Noise control is treated as a feature, not a detail: verified-publisher
suppression, a post-install learning window, per-program/destination "always
allow", and severity gating so only serious findings interrupt you.

## Status

Feature complete against the original design; **not yet validated on real
hardware over time.** The false-positive rate during ordinary use is the open
question.

- Design: [docs/plans/2026-07-24-nitewatch-design.md](docs/plans/2026-07-24-nitewatch-design.md)
- Phase plans: [P1](docs/plans/2026-07-25-p1-flight-recorder.md) · [P2](docs/plans/2026-07-25-p2-detections.md)
- Feed licensing (read before adding a source): [docs/feed-licensing.md](docs/feed-licensing.md)
- Known limitations: [agent/internal/help/known-limitations.md](agent/internal/help/known-limitations.md)
  — compiled into the binary and readable in the dashboard under **Limits**, so it
  travels with a build rather than living only in this repository

## Running it

Build (pure-Go, single static exe, no CGO):

```bash
cd agent && CGO_ENABLED=0 go build -o nitewatch ./cmd/nitewatch
```

Cross-compile for Windows:

```bash
cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/nitewatch.exe ./cmd/nitewatch
```

`-trimpath` matters: builds are reproducible, and released binaries have their
SHA-256 published, so a build made without it will not match the hash on the
download page even when the source is identical.

`dist/` is git-ignored build output. To hand someone a working copy, ship the
exe together with `agent/scripts/run-nitewatch.bat` — that launcher is the
source of truth, and it must sit in the same directory as the exe because it
self-elevates and then runs `nitewatch.exe` from its own location.

**`dist/` is where a build is picked up from, so rebuild it whenever the thing
being handed over changes.** A stale exe there is indistinguishable from a
current one at a glance, and the file's timestamp does not help: Go stamps the
*commit* time into the binary, not the build time, so a fresh build of old code
and an old build of old code look the same. To check what a binary actually is:

```bash
go version -m dist/nitewatch.exe | grep vcs
```

The running agent reports the same identity in its About panel, which is the
only way to check on a machine without Go.

**Windows (live)** — must run **elevated**; ETW requires Administrator:

```
nitewatch.exe --serve
```

Or double-click `run-nitewatch.bat`, which requests elevation for you. Then
open <http://127.0.0.1:8973>.

**Dev/demo (any OS)** — replay a recorded trace, no elevation needed:

```bash
./nitewatch --replay testdata/traces/basic.jsonl
```

Useful flags: `--no-feeds` (skip threat-intel downloads), `--no-recon` (skip the
address-ownership dataset), `--rules <dir>` (load rule packs from disk during
development). Everything else is configured from the dashboard's Settings panel.

## Layout

```
agent/
  cmd/nitewatch/     entrypoint and run modes
  internal/
    source/          telemetry: Windows ETW, and a JSONL replay source for tests
    event/           the source-agnostic event vocabulary
    graph/           causal event graph (GoRapide poset) + rolling window
    ledger/          SQLite flight recorder: connections, alerts, actions
    detect/          detection engine, detectors, suppression gates
    filewatch/       file classification and encryption-burst tracking
    autostart/       autostart snapshot + diff
    intel/           threat-intel feeds, matched offline
    recon/           offline address ownership (ASN, country)
    respond/         remediation actions and undo
    notify/          notification gating and Windows toasts
    api/             loopback HTTP + embedded dashboard
  rules/             shipped detection rule packs (YAML), embedded in the binary
  testdata/traces/   replay fixtures
```

## Third-party data

See [NOTICE](NOTICE) for required attributions.

## Licence

Copyright © 2026 Threat Tape LLC.

NiteWatch is free software, licensed under the **GNU General Public License
version 3 or later**. See `LICENSE` for the full text.

The licence is not a preference so much as an inheritance: the Windows
event-tracing consumer this agent depends on (`github.com/0xrawsec/golang-etw`)
is GPL-3.0, and linking it makes the whole program GPL-3.0. Check a
dependency's licence before you ship a binary, not after.

Every source file carries an SPDX header. `agent/internal/help/licenses.md` is
compiled into the binary and shown in the dashboard's **Limits & roadmap**
panel, which is where the GPL wants an interactive program's legal notices to
be, and where the threat-intel feeds require their attributions to appear.

Third-party components and their licences are listed in that document. The
short version: golang-etw and golang-utils are GPL-3.0, gorapide is MIT,
golang.org/x/sys and the modernc.org SQLite stack are BSD-3-Clause.
