# NiteWatch P2 "Detections" Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn the P1 flight recorder into a detector — match causal patterns and threat-intel against the live event graph, and raise plain-English, causally-explained alerts with "Do this…" advisories for the two P2 detection areas: **C2 / phone-home** and **persistence / implant install**.

**Architecture:** A rule engine evaluates signed, hot-loaded rule packs (GoRapide `pattern` expressions + predicates) against the rolling causal window on every ingested event. Matches enrich against a locally-cached threat-intel store (abuse.ch feeds, pulled down, matched offline) and pass noise-control gates (known-good signer suppression, ledger novelty, allowlist). Survivors become `Detection`s → rendered through per-rule narrative templates (deterministic, no LLM) into `Alert`s that carry a serialized Mermaid causal subgraph. Alerts surface via the loopback API + a dashboard alert page and (Windows) a toast. **No response execution yet — that's P3.** P2 advises; the user acts manually.

**Tech Stack:** builds on P1 (Go agent, GoRapide, SQLite ledger, loopback API, replay source). Adds: `pattern`/`constraint` GoRapide packages, `gopkg.in/yaml.v3` (rule packs), `golang.org/x/mod/sumdb/note` or ed25519 (pack signing), Windows registry-ETW + Authenticode (behind build tags), Windows toast via `go-toast`-style PowerShell fallback.

---

## Read First

- `docs/plans/2026-07-24-nitewatch-design.md` — detection areas, feeds, noise control, advisory rules.
- `docs/plans/2026-07-25-p1-flight-recorder.md` — the building blocks this extends.
- P1 code: `internal/event` (vocabulary), `internal/graph` (causal window + `DomainFor`), `internal/ledger` (`IsNewDestination`), `internal/source` (the `//go:build windows` sensor pattern), `internal/api` (loopback server + embedded dashboard).

## Design Constraints Carried From P1

- **Templated advisories only** — hand-written narrative + playbook per rule. No LLM in the alert path.
- **Local-first** — feeds are pulled *down*; nothing about the user's machine goes *up*.
- **CGO-free**, single static exe. New deps must be pure-Go.
- **Windows-only sensors** (registry, signer) sit behind `//go:build windows` with replay fixtures for tests, exactly like P1's ETW source. Everything else is WSL2-testable via synthetic traces.

---

## Task 0: Extend the event vocabulary for persistence + signer

Persistence detection needs registry/autostart events; C2 signer-rules need to know if the acting binary is signed.

**Files:** Modify `agent/internal/event/event.go`; Test `agent/internal/event/event_test.go`

**Steps:**
1. Add kinds: `KindRegPersist` (Run keys, services, scheduled-task, startup-folder, WMI subscription writes) and reuse `KindProcStart` for signer data.
2. Add fields to `NormalizedEvent`: `Signed bool`, `Signer string` (Authenticode subject; empty/unsigned by default), and for persistence `PersistKind string` (`"run-key"|"service"|"scheduled-task"|"startup-folder"|"wmi"`), `PersistTarget string` (the value/path being installed), `PersistLocation string` (the hive/key/path written).
3. Test: a `KindRegPersist` event round-trips through JSON with its persist fields. Red → implement → green → commit.

---

## Task 1: Threat-intel feed store (WSL2-testable)

A local, offline matcher over public feeds. Downloads are the only network egress and are plain feed pulls (no user data leaves).

**Files:** Create `agent/internal/intel/intel.go`, `agent/internal/intel/feeds.go`; Test `agent/internal/intel/intel_test.go`; fixtures `agent/testdata/feeds/{threatfox_ips.txt,urlhaus_domains.txt}`

**Steps:**
1. **Test first:** build a `Store` from fixture files; assert `store.FlagIP("185.4.3.2")` returns a `Match{Feed:"threatfox", Reason:"..."}` and a clean IP returns none; same for `FlagDomain`.
2. Implement `Store` with `map[string]Match` sets for IPs and domains, plus `LoadFile(path, feed)` parsers tolerant of abuse.ch CSV/plain formats (skip `#` comments).
3. Add `Refresh(ctx, sources []Source)` that HTTP-GETs each feed URL to a temp file, parses, and atomically swaps the in-memory sets behind a `sync.RWMutex`. Sources: ThreatFox IP-port, Feodo Tracker, URLhaus host list, Tor exit list (loaded as *context* tag, not auto-flag).
4. Add a `RefreshLoop(ctx, every)` goroutine (default 6h). All matching is offline against the cached sets.
5. Green → commit. **Decision to document:** feed cadence + which feeds are auto-flag vs context-only (Tor = context).

---

## Task 2: Rule-pack format + signed loader (WSL2-testable)

Rules are data, hot-loaded, signed so a tampered pack is rejected.

**Files:** Create `agent/internal/rules/pack.go`, `agent/internal/rules/loader.go`; Test `agent/internal/rules/loader_test.go`; `agent/rules/` (shipped packs, embedded as defaults)

**Rule schema (YAML):**
```yaml
id: c2-feed-flagged-connection
area: c2                      # c2 | persistence
severity: critical           # low|medium|high|critical
title: "{{.Image}} is contacting a server flagged for malware control"
match:                       # one of the named detectors (Task 3 dispatch)
  detector: connection-intel-hit
narrative: |
  {{.ImageShort}} opened a connection to {{.RemoteDest}}, which appears on the
  {{.FeedName}} threat-intelligence feed ({{.FeedReason}}). Programs contact
  flagged infrastructure like this when they are remote-controlled by an attacker.
playbook:
  - "Disconnect this device from the network (turn off Wi-Fi) if you did not expect this."
  - "Note the program name: {{.Image}}"
  - "Run a full Microsoft Defender scan."
```

**Steps:**
1. **Test first:** `LoadPack(bytes)` parses the YAML into a `Pack{Rules []Rule}`; a rule with an unknown `severity` errors; templates compile (parse `title`/`narrative`/`playbook` as `text/template`, fail fast on bad syntax).
2. Implement `Rule` (with pre-parsed `*template.Template`s) + `LoadPack`.
3. **Signing:** `LoadSignedPack(data, sig, pubkey)` verifies an ed25519 detached signature over the pack bytes before parsing; `verify_test.go` covers good sig / tampered pack / wrong key. Ship packs are embedded via `go:embed rules/*.yaml` plus their `.sig`. Document the key-management choice (dev key in repo for now; release key rotation is a P3+ ops item).
4. Green → commit.

---

## Task 3: Detection engine (WSL2-testable)

Evaluates rules against the causal window per event and emits `Detection`s. Named detectors keep rule YAML declarative while the matching logic (some needing GoRapide patterns, some needing ledger/intel lookups) lives in Go.

**Files:** Create `agent/internal/detect/engine.go`, `agent/internal/detect/detectors.go`; Test `agent/internal/detect/engine_test.go`

**Steps:**
1. **Test first:** feed a synthetic trace (browser → raw-IP connect with no DNS) through the engine wired to a stub intel store; assert exactly one `Detection` with `RuleID == "c2-raw-ip-no-dns"` and that it carries the matched connection's `EventID` (for subgraph extraction later).
2. Implement `Engine{rules, intel, ledger}` with `OnEvent(g *graph.Graph, id gr.EventID, e event.NormalizedEvent) []Detection`. Dispatch on each rule's `detector`:
   - `connection-intel-hit` — `NetConnect` whose IP/domain hits `intel.FlagIP/FlagDomain`.
   - `raw-ip-no-dns` — `NetConnect` where `graph.DomainFor(id) == ""` **and** the process had no preceding DNS (a GoRapide `Not(Seq(DNSQuery, NetConnect))`-style check over the process subgraph).
   - `beaconing` — ≥N connections from one process to one dest at near-constant intervals (ledger query over recent rows; `constraint`-style count/timing check).
   - `unsigned-outbound` — first outbound connection by an `Unsigned` process not seen before (`ledger.IsNewDestination` + `!e.Signed`).
3. A `Detection` carries `RuleID, Area, Severity, AnchorID (EventID), Fields map[string]any` (the template data). Green → commit.

---

## Task 4: C2 rule pack (WSL2-testable)

**Files:** Create `agent/rules/c2.yaml` (+ `.sig`); extend `agent/testdata/traces/` with `c2_beacon.jsonl`, `c2_rawip.jsonl`; Test `agent/internal/detect/c2_test.go`

**Steps:** author the four C2 rules (feed-flagged, raw-ip-no-dns, beaconing, unsigned-outbound) with narratives + playbooks per the design doc. Table-test each synthetic trace → expected rule fires with correctly-filled narrative (assert the rendered string contains the process + destination). Green → commit.

---

## Task 5: Registry + signer sensors (Windows-only; stubs + fixtures)

Mirror P1's ETW pattern: real Windows implementation behind `//go:build windows`, a `!windows` path, and replay fixtures driving the tests.

**Files:** Create `agent/internal/source/reg_windows.go` (add `Microsoft-Windows-Kernel-Registry` provider + map autostart-location writes to `KindRegPersist`), `agent/internal/enrich/signer_windows.go` (Authenticode check via `wintrust`/`Get-AuthenticodeSignature`-equivalent) + `signer_stub.go`; Test with a persistence replay fixture.

**Steps:**
1. Extend the Windows ETW source to subscribe to the registry provider and translate writes under Run/RunOnce keys, service-image paths, scheduled-task registration, startup folder, and WMI subscription namespaces into `KindRegPersist` events with `PersistKind/Target/Location`.
2. Signer enrichment: on `KindProcStart`, populate `Signed`/`Signer` (Windows only; `Signed=false` elsewhere). Cache by image path+hash to avoid re-checking.
3. Cross-compile gate (`GOOS=windows go build/vet`) + extend the VM smoke-test README with a persistence-trigger walk-through (e.g. add a Run-key value, expect an alert). Commit.

---

## Task 6: Persistence rule pack (WSL2-testable)

**Files:** Create `agent/rules/persistence.yaml` (+ `.sig`); fixture `agent/testdata/traces/persist_runkey.jsonl` (browser → dropped exe → Run-key write); Test `agent/internal/detect/persistence_test.go`

**Steps:** add a `persistence-autostart` detector — a `KindRegPersist` correlated with the writing process's lineage, suppressed when the writer is a known-good signed installer (Task 8 gate). Rules per autostart type with narratives ("*invoice.exe*, which you downloaded 3 minutes ago, just set itself to run every time you start Windows"). Table-test. Green → commit.

---

## Task 7: Alert store + narrative templating + causal subgraph (WSL2-testable)

Turn `Detection`s into persisted `Alert`s that keep their story after the live poset window rolls off.

**Files:** Create `agent/internal/alert/alert.go`, `agent/internal/alert/store.go` (new SQLite table `alerts`); Test `agent/internal/alert/alert_test.go`

**Steps:**
1. **Test first:** given a `Detection` + the current graph, `Render` produces an `Alert{Narrative, Playbook []string, Severity, MermaidGraph, Evidence}` with the narrative template filled and `MermaidGraph` non-empty.
2. Implement `Render(d Detection, g *graph.Graph)`: pull `g.Poset().CausalAncestors(d.AnchorID)` ∪ anchor to get the story subgraph, render it via GoRapide's Mermaid export with `HighlightPath` on the anchor chain; execute the rule's templates against `d.Fields`.
3. Persist to an `alerts` table (id, ts, rule_id, severity, narrative, playbook_json, mermaid, evidence_json, status='new'). Add `RecentAlerts`, `AckAlert`. Green → commit.

---

## Task 8: Noise control (WSL2-testable)

The make-or-break layer. A `Detection` must clear these gates before becoming an `Alert`.

**Files:** Create `agent/internal/detect/suppress.go`, allowlist table in `internal/ledger` or a new `internal/allow`; Test `suppress_test.go`

**Steps:**
1. **Signer suppression:** signed-by-known-good (Microsoft, major vendors list) processes don't fire persistence/unsigned rules. Test: a signed installer writing a Run key produces no alert; an unsigned one does.
2. **Novelty weighting:** use `ledger.IsNewDestination` so long-established process↔dest pairs stop re-alerting; only first-sighting (or feed-flagged) fires.
3. **Allowlist:** `allow.Add(ruleID, subjectKey)` + `allow.Suppressed(...)`; an "always allow" decision persists and suppresses future identical detections. Test add-then-suppress.
4. **Per-install learning window:** a freshly-installed program gets a short grace window where its autostart writes are surfaced as *low* severity ("new program X configured itself to start automatically — expected?") rather than *high*. Green → commit.

---

## Task 9: Alert API + dashboard alert view (WSL2-testable)

**Files:** Modify `agent/internal/api/server.go` (+ `/api/alerts`, `/api/alerts/{id}`, `POST /api/alerts/{id}/ack`); add `agent/internal/api/dashboard/` alert views (extend the embedded page); Test `server_test.go`

**Steps:**
1. **Test first:** seed an alert; `GET /api/alerts` returns it newest-first; `GET /api/alerts/{id}` includes the Mermaid graph + playbook; `POST .../ack` flips status.
2. Dashboard: add an **Alerts** panel (severity-colored list) and an alert detail view — narrative at top, the causal story rendered from the stored Mermaid (client-side mermaid via a vendored, embedded script — no CDN, honoring the no-external-fetch rule), an evidence table, and the "Do this" playbook as a numbered checklist. **Actions are display-only in P2** (copy-able commands / manual steps); one-click execution is P3.
3. Green → commit + `run`-skill smoke test in replay mode against a malicious trace: confirm an alert renders with its story graph.

---

## Task 10: Windows toast notifications (Windows-only)

**Files:** Create `agent/internal/notify/toast_windows.go` + `toast_stub.go`; Test the severity-gating logic cross-platform (the gate is pure Go; only the toast call is Windows).

**Steps:** severity tiers gate interruption per design doc — Critical = takeover-style toast, High = actionable toast, Medium/Low = tray-badge only (no toast). On non-Windows, `Notify` is a logged no-op. Toast body = alert headline + "Open NiteWatch" that deep-links to `http://127.0.0.1:8973/#/alerts/{id}`. Commit.

---

## Task 11: Wire detection into the collector + main; feeds refresh; smoke test

**Files:** Modify `agent/internal/collector/collector.go` (run the engine per event; render+persist+notify on detection), `agent/cmd/nitewatch/main.go` (construct intel store + refresh loop + rule packs + alert store; `--rules <dir>` override, `--no-feeds` offline flag)

**Steps:**
1. Collector calls `engine.OnEvent(...)` after ingest; each surviving `Detection` → `alert.Render` → `store` → `notify`.
2. Main wires intel `RefreshLoop`, loads embedded+`--rules` packs, opens the alert store.
3. **End-to-end smoke test (replay, WSL2):** `nitewatch --replay testdata/traces/c2_rawip.jsonl --serve --no-feeds` → dashboard shows a C2 alert with narrative + causal story. Full suite `-race` green, `go vet` clean both targets, CGO-free build both targets. Commit + push.

---

## Definition of Done (P2)

- C2 and persistence packs fire correctly on synthetic traces; narratives render with real specifics; noise-control gates verified (signed-good suppressed, novelty limits repeats, allowlist sticks).
- Alerts persist with their causal story and survive window rollover.
- Dashboard shows alerts + drill-down story graph; playbooks display "Do this" steps (no execution yet).
- Full suite `-race` green; `go vet` clean linux+windows; CGO-free static exe both targets.
- **Manual Windows-VM smoke test** (owed, like P1): trigger a Run-key persistence + a connection to a feed-flagged IP; confirm toast + alert with correct story.
- **Deferred to P3:** one-click response actions (kill/block/quarantine/undo) with undo, and the ransomware + sensitive-file packs.

---

## Notes for the Executor

- Reuse P1's testability seam: synthetic `.jsonl` traces + replay source drive every detector test. Registry/signer/toast Windows paths stay build-gated with fixtures.
- Narrative templates are the product's voice — write them for a scared non-technical user, not an analyst. No jargon in `narrative`/`playbook`; keep the jargon in the evidence table.
- Vendor the mermaid JS into the embedded dashboard assets — the CSP/no-external-fetch rule from the design doc applies to the local UI too.
- Keep detectors cheap: they run on every ingested event. Prefer indexed ledger lookups and bounded subgraph walks over full-poset scans.
- Follow superpowers:test-driven-development per task: red → green → commit.
