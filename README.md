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

Pre-implementation. Design validated 2026-07-24 — see
[docs/plans/2026-07-24-nitewatch-design.md](docs/plans/2026-07-24-nitewatch-design.md).

## Layout (planned)

```
agent/        Go agent: ETW sensors, causal graph (GoRapide), rule engine, ledger
dashboard/    SvelteKit localhost UI: Who's Talking, alerts, allowlists
rules/        Signed detection rule packs (JSON/YAML)
docs/plans/   Design documents and implementation plans
```
