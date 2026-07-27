# NiteWatch — Project Context

## What This Is

NiteWatch is a lightweight personal endpoint defense agent for Windows — a consumer
"EDR-lite." It watches the machine via userland ETW, builds a live causal event graph
(GoRapide poset), logs every outbound connection to a persistent ledger ("who is
talking to what and when"), and surfaces plain-English alerts with one-click "Do
this..." remediation. The differentiator is the causal story: not "threat quarantined"
but "this PDF spawned a script that is phoning home to X and rewriting your Documents."

First **consumer** product in the Threat Tape portfolio (everything else is B2B).

## Design Doc

`docs/plans/2026-07-24-nitewatch-design.md` — validated 2026-07-24. Read it before any
implementation work. All core decisions (platform, response mode, privacy stance,
engine, detections, UX, advisory generation) are recorded there with alternatives.

## Stack

- **Agent:** Go (single static exe, Windows service + tray companion in one binary)
  - Causal engine: `github.com/ShaneDolphin/gorapide` (MIT) — poset, pattern language,
    constraint checker, Mermaid/DOT export
  - Ledger: SQLite via `modernc.org/sqlite` (pure Go — keep the build CGO-free)
  - Telemetry: userland ETW consumers. **No kernel driver, ever, in this product line.**
- **Dashboard:** SvelteKit, served by the agent on localhost only
- **Rules:** signed JSON/YAML rule packs (data, not code), hot-loaded
- **Intel feeds:** abuse.ch (ThreatFox/Feodo/URLhaus), Tor exits — pulled down,
  matched locally

## Hard Constraints

- **Privacy:** no telemetry leaves the machine. Feeds are pull-only. Per-address queries
  to third parties are allowed **only** when the user explicitly triggers one, on a
  control that states what it will do first — currently the RDAP registration lookup
  (`internal/rdap`), plus the planned anonymous hash lookup. Nothing automatic — no
  ingest path, timer, or page load — may make one. Reverse DNS is the standing exception
  and is disableable.
- **Advisories are templated per rule** — deterministic, hand-written narrative +
  playbook. No LLM-generated security advice in the alert path.
- **Response actions** use standard OS facilities (taskkill semantics, Windows
  Firewall rules, ACLs) and must have an undo path where one exists.
- **False-positive budget is a first-class test target** — a week-long "quiet machine"
  soak must produce zero alerts.
- Dev box is WSL2/Linux; Windows-specific behavior (ETW, toasts, service install)
  needs a Windows VM or test host — cross-compile with `GOOS=windows`.

## Phasing (see design doc for detail)

1. **P1 — Flight recorder:** sensors + causal graph + connection ledger + dashboard
2. **P2 — Detections:** rule engine, C2 + persistence packs, alert UX, feeds
3. **P3 — Response:** one-click actions with undo
4. **P4:** ransomware + sensitive-file packs, novelty scoring, installer/signing

## Testing

- Unit: replay recorded ETW traces as poset fixtures; assert rules match with the
  right causal subgraph
- Integration: Atomic Red Team atomics in a disposable Windows VM
- Soak: quiet-machine false-positive budget
