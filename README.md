# NiteWatch

**Somebody's knocking on your door at 3am. Here's who.**

NiteWatch is a lightweight personal security agent for Windows. It watches what your
computer is actually doing — which programs are running, who they're talking to, what
files they're touching — and when something is wrong, it tells you the story in plain
English with a one-click fix.

- **Who's talking?** A permanent, process-attributed log of every outbound connection:
  which program, which server, which domain, when.
- **The whole story.** Alerts show the causal chain, not a jargon blob: "downloaded
  ZIP → extracted EXE → spawned PowerShell → contacted a server flagged for malware
  control."
- **Do this.** Every alert comes with a pre-built fix: kill it, block it, quarantine
  it, undo what it changed — one click, with undo.
- **Private by design.** Everything is analyzed on your machine. Threat intelligence
  is pulled *down*; your data never goes *up*.

## Status

**P1 "Flight Recorder" implemented** (2026-07-25) — the causally-enriched,
process-attributed connection ledger + "Who's talking?" dashboard. Detections,
alerts, and response actions come in P2+.

- Design: [docs/plans/2026-07-24-nitewatch-design.md](docs/plans/2026-07-24-nitewatch-design.md)
- P1 plan + status: [docs/plans/2026-07-25-p1-flight-recorder.md](docs/plans/2026-07-25-p1-flight-recorder.md)

## Running it

Build (pure-Go, single static exe, no CGO):

```bash
cd agent && CGO_ENABLED=0 go build -o nitewatch ./cmd/nitewatch
```

**Dev/demo (any OS)** — replay a recorded trace and serve the dashboard:

```bash
./nitewatch --replay testdata/traces/basic.jsonl --serve
```

Then open <http://127.0.0.1:8973>.

**Windows (live)** — run the built `nitewatch.exe` **elevated**:

```
nitewatch.exe --serve
```

ETW requires Administrator. On non-Windows the live source is unavailable — use
`--replay`. See [agent/internal/source/README.md](agent/internal/source/README.md)
for the Windows-VM smoke test.

## Layout (planned)

```
agent/        Go agent: ETW sensors, causal graph (GoRapide), rule engine, ledger
dashboard/    SvelteKit localhost UI: Who's Talking, alerts, allowlists
rules/        Signed detection rule packs (JSON/YAML)
docs/plans/   Design documents and implementation plans
```
