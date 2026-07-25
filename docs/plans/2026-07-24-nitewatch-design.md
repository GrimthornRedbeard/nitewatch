# NiteWatch — Design Document

**Date:** 2026-07-24
**Status:** Validated via brainstorm with Kevin; ready for implementation planning
**Product:** NiteWatch — a lightweight personal endpoint defense agent for Windows

## One-liner

Enterprise EDRs build causal process graphs and show them to SOC analysts. Consumer AV
says "threat quarantined" and explains nothing. NiteWatch sits in the unserved middle:
it watches a personal Windows machine, builds a live causal graph of what's happening,
and when something is wrong it tells the user the *story* in plain English — "this PDF
you opened spawned a script that is contacting a server flagged for malware control and
rewriting your Documents folder" — with one-click "Do this" remediation.

## Core Decisions (from 2026-07-24 brainstorm)

| Decision | Choice | Alternatives considered |
|---|---|---|
| v1 platform | **Windows** (ETW telemetry, userland) | Linux (eBPF, tiny consumer market), macOS (EndpointSecurity entitlement gauntlet), cross-platform day-1 (triples sensor work) |
| Response mode | **Advise + one-click respond** — userland observation, agent executes remediation on user click via standard OS facilities. No kernel driver, no WHQL signing. | Advise-only (weaker product), full active blocking (requires signed minifilter/WFP drivers; competes with Defender head-on) |
| Local vs cloud | **Local + public feeds** — all telemetry/analysis on-device; agent pulls down free intel feeds; optional anonymous hash lookups user can disable | 100% air-gapped (stale intel), cloud-assisted (privacy irony, PII infrastructure burden) |
| Engine | **All-Go on GoRapide** (github.com/ShaneDolphin/gorapide, MIT) — single static exe; GoRapide poset = causal graph; its pattern/constraint packages = detection-rule engine; Mermaid/DOT export drives the story UI | Go sensors + PyRapide analyzer (two runtimes, Python-on-Windows packaging pain), bespoke engine (more control, more work) |
| v1 detections | **All four, staged:** C2/phone-home, ransomware-pattern file activity, persistence/implant install, sensitive-file access (last — heaviest allowlist tuning) | — |
| UX surface | **Tray + toast + local web UI** — tray icon (green/yellow/red), Windows toasts, localhost SvelteKit dashboard with causal story graph | Native WinUI3/WPF app (new stack), toast-only (loses the storytelling differentiator) |
| Advisory generation | **Templated per rule** — each rule ships a hand-written narrative template + remediation playbook, filled from the matched causal subgraph. Deterministic, auditable, zero hallucination risk, offline. | Templates + opt-in LLM "explain more" (possible v2), local LLM narration (multi-GB dependency, hallucinated security advice is product-killing) |
| Name | **NiteWatch** (evolved: Sentry → rejected, sentry.io trademark; Nightwatch → NiteWatch to separate from Nightwatch.js in search/trademark) | Causeway, HomeTape, WatchTape, TraceIQ, Warden, Palisade |

## Architecture

A single Go executable running as an elevated Windows service, with a tray companion in
the same binary (different launch mode). Four layers in one process:

```
ETW Sensors → Causal Graph (GoRapide poset) → Rule Engine (patterns + constraints) → Advisory / UX
```

### Sensor layer (userland ETW, no kernel driver)

- `Microsoft-Windows-Kernel-Process` — process create/exit, image loads
- `Microsoft-Windows-Kernel-Network` — TCP/UDP connects
- `Microsoft-Windows-Kernel-File` — file create/write/delete/rename
- `Microsoft-Windows-DNS-Client` — name resolutions
- Registry events for persistence locations (Run keys, services, tasks, WMI subscriptions)

Each raw ETW event is normalized into a GoRapide `Event` with typed params.

### Causal graph layer (the differentiator)

Sensors wire causal edges as events arrive: process-create links child→parent;
network/file/registry events link to the acting process's poset node; DNS resolutions
link to the connections that follow them. The poset is a live "who caused what" DAG.

Memory bounding: rolling window of ~15–30 minutes of poset history; process-lineage
nodes pinned longer. Consumer machines are far quieter than enterprise servers, so this
is tractable.

### Rule engine

GoRapide `pattern` + `constraint` checks run against the stream. Rules are **data**
(signed rule-pack files, hot-loaded), not code — detection updates don't require
re-shipping the binary.

### Advisory / UX layer

Matched rules render into toasts and the localhost dashboard using the rule's narrative
template filled from the matched causal subgraph.

## Connection Ledger (network flight recorder)

Every outbound connection is logged whether or not a rule fires — "who is talking to
what and when." Record fields: timestamp; process (name, path, PID, hash, signer);
remote IP + port; protocol; **resolved domain name** (joined from DNS-Client events in
the causal graph — the thing netstat can never tell you); bytes in/out; duration;
verdict (clean / feed-flagged / alert-linked).

**Storage — two tiers:**

- **Ledger** (SQLite via `modernc.org/sqlite`, pure Go, CGO-free): connection records,
  alert history, allowlist decisions. Default retention ~90 days with size cap,
  user-configurable.
- **Poset** (in-memory, rolling window): too chatty to persist whole. When a rule
  fires, the matched causal *subgraph* is serialized into the alert record — the story
  behind every alert survives after the live window rolls off.

**Dashboard "Who's talking?" page:** filterable/searchable table (process, domain, time
range) + rollups: top talkers, never-seen-before destinations this week, feed-flagged
connections. "First time this process contacted this domain" falls out of the ledger
for free and feeds novelty scoring back into the rule engine.

The ledger is also the substrate for future features (monthly security report,
cross-device view).

## Detection Rules & Intel Feeds

**Rule packs:** signed JSON/YAML, hot-loaded. Each rule = GoRapide pattern expression +
severity + narrative template + playbook.

Example rules per area:

- **C2 / phone-home:** unsigned-or-new binary makes outbound connection
  (`Seq(ProcessStart[unsigned], NetConnect)`); regular-interval beaconing to one host;
  connection to feed-flagged IP/domain; process connecting to a raw IP with **no prior
  DNS resolution** (no DNS parent in the causal graph — classic malware tell).
- **Ransomware pattern:** `Within(fan_out(FileWrite × N across user dirs), 60s)` from
  one process; escalate hard on shadow-copy deletion (`vssadmin delete`), mass
  rename-to-new-extension, ransom-note-name drops.
- **Persistence:** writes to Run keys, new scheduled tasks/services, startup-folder
  drops, WMI event subscriptions — correlated with the writing process's lineage
  (signed installer = normal; script spawned by a browser download = not).
- **Sensitive-file access:** reads of browser credential stores, SSH keys, wallet
  files by any process that isn't the owning app or an allowlisted backup tool.

**Feeds** (pulled down over HTTPS a few times daily; matched locally; nothing leaves
the machine): abuse.ch ThreatFox + Feodo Tracker (C2 IPs/domains), URLhaus (malware
URLs), Tor exit list (context, not auto-flag), known-good signer info for suppression.

**Noise control (make-or-break):** known-good signer suppression; learning window per
new install ("this is your backup tool touching everything — allow?"); one-click
"always allow" from the alert; novelty-weighted scoring from the ledger so established
behavior stops re-alerting.

## Response Actions & Alert UX

One-click actions via standard OS facilities, each with an undo path where one exists:

- **Kill process tree** — terminate the flagged process and its causal descendants
  (the poset identifies exactly which children are part of the incident).
- **Block the destination** — Windows Firewall outbound rule for the remote IP/domain
  + per-executable block. Undoable from the dashboard.
- **Quarantine the file** — move to locked quarantine dir, strip execute ACLs, record
  original path for restore.
- **Undo persistence** — delete the exact Run key / task / service entry that was
  written (we logged the write, so reversal is surgical).
- **Escalate** — "run a full Defender scan" / "disconnect Wi-Fi" guidance; exportable
  incident report (causal subgraph + ledger slice) for taking to a pro.

**Alert anatomy.** Toast: severity color, one-sentence headline ("*photos_backup.exe*
is sending data to a server flagged for malware control"), buttons **Fix it** /
**Details** / **Allow**. "Fix it" runs the rule's playbook (pre-selected actions).
"Details" opens the dashboard alert page: plain-English narrative → causal story graph
(Mermaid from the matched subgraph: "downloaded ZIP → extracted EXE → spawned
PowerShell → contacted 185.x.x.x") → evidence table → actions with checkboxes.

**Severity tiers gate interruption:** Critical (ransomware-pattern) = takeover toast;
High = actionable toast; Medium/Low = tray badge only, reviewed at leisure. Consumer
trust dies by nagging.

## Phasing

1. **P1 — Flight recorder:** ETW sensors + causal graph + connection ledger + "Who's
   talking?" dashboard. No detections yet — already a usable product (causally
   enriched, process-attributed netstat).
2. **P2 — Detections:** rule engine + C2 and persistence packs + toast/alert UX + feeds.
3. **P3 — Response:** one-click actions with undo, quarantine, firewall blocks.
4. **P4 — Hard stuff:** ransomware-pattern pack, sensitive-file pack (allowlist-tuning
   heavy), novelty scoring, installer/code-signing/auto-update.

## Testing Strategy

- **Unit:** rule-pattern matching against recorded posets — capture real ETW traces
  once, replay as fixtures. Deterministic; no live malware needed.
- **Integration/smoke:** Atomic Red Team atomics in a disposable Windows VM — each
  atomic maps to a rule that must fire *with the right causal story*.
- **False-positive budget:** "quiet machine" soak test — zero alerts across a week of
  normal use is a first-class test target.

## Portfolio Fit

First consumer product in the Threat Tape stable (everything else is B2B/appliance).
Go/ETW sensor work is new muscle; the dashboard is SvelteKit (existing portfolio
strength); Uncle Grimmy is the natural brand voice ("Somebody's knocking on your door
at 3am, kid. Here's who.").

**Naming note:** trademark screen still to be done before public launch. Known
neighbors: Nightwatch.js (BrowserStack browser-testing framework — different category;
NiteWatch spelling further separates), sentry.io (avoided entirely). Domain candidates:
getnitewatch.com, nitewatch.threattape.com.

## Open Items

- [ ] Trademark/domain collision sweep for "NiteWatch"
- [ ] Evaluate Go ETW consumer libraries (e.g. bi-zone/etw, 0xrawsec/golang-etw) vs
      wrapping `krabsetw`-style sessions directly
- [ ] Verify GoRapide poset throughput against a realistic consumer ETW event rate;
      define eviction strategy details
- [ ] Rule-pack signing scheme (minisign/ed25519?)
- [ ] Decide elevation model: single elevated service + non-elevated tray/UI over
      localhost, vs single elevated process
