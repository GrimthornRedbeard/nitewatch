# nitewatch — Code Review (November 2026)

Reviewed at `cb4eee6` (main, = published `v0.1.8-pre` + one ORCHESTRATOR.md commit) on 2026-11-13. Read-only review; no changes made.

## Summary

NiteWatch is a single-binary Go agent (~12k lines of product Go, ~7.6k lines of tests, one 2.85k-line embedded HTML dashboard). It reads Windows ETW, builds a GoRapide causal graph, records connections to SQLite, runs templated detections, and serves a loopback dashboard with one-click remediation. Overall the code is careful. Comments explain why, the tests run in about 5 s and pass, and `go vet`, `gofmt` and `staticcheck` are clean on both linux and windows. The real problems are in the **trust model around the local API** and in a few **wiring gaps** that the unit tests never cover because each package is tested on its own. The changes that matter most:

1. **The API token is handed to anyone who asks.** `GET /` is unauthenticated and returns the token in the page (reproduced live). The token therefore stops nothing, and two of the three protections the shipped Known Limitations document promises are false (R-01).
2. **The elevated agent acts on records from a database the user can write.** Undo validation does not limit where a restored file may land, or what value is written back into the HKLM Run, Winlogon or IFEO keys. Combined with R-01, that gives any same-user process admin-level actions (R-02).
3. **Network alerts never raise a toast.** That includes the critical "contacting known malware infrastructure" and "uploaded right after reading your passwords" alerts. Only file and persistence alerts notify (R-03).
4. **"Always allow" silently does nothing for credential-theft and persistence alerts.** Reproduced: the same program alerted again on its next run (R-05).
5. **The per-packet hot path and the 5-second dashboard poll run unindexed full-table SQL** — about 15 ms per network event and about 150 ms per poll at 200k rows (R-06, R-07). The released toolchain also has one new reachable stdlib vuln, so Gate 6's "no vulnerabilities" is now stale (R-08).

## Scope & coverage

| Area | Prod LOC | Test LOC | Depth |
|---|---|---|---|
| `agent/internal/api` (server, auth) | 1,203 | 496 | **Read in full** |
| `agent/internal/collector` | 788 | 439 | **Read in full** (the ingest hot path) |
| `agent/internal/ledger` (+ `schema.sql`) | 722 | 722 | **Read in full**; query plans measured |
| `agent/internal/respond` (+ `exec_windows.go`) | 681 | 318 | **Read in full** |
| `agent/cmd/nitewatch/main.go` | 433 | 0 | **Read in full** |
| `agent/internal/detect` | 1,666 | 1,825 | engine, suppress, persistence/files fields read; beacon/exfil skimmed |
| `agent/internal/graph` | 1,132 | 882 | window.go read; graph.go accessors read; occupancy/story/narrate skimmed (recently fixed and well-tested) |
| `agent/internal/source` (ETW, replay, namecache) | 771 | 233 | provider list + Kernel-Network/File normalisation read |
| `agent/internal/platform` (Windows signer/identity/proctable) | 543 | 0 | signer + identity read |
| `intel`, `recon`, `resolve`, `rules`, `notify`, `settings`, `selftest` | ~2.5k | ~1.2k | download/refresh paths, caches, locking read; selftest drill PIDs checked |
| `rdap`, `vt`, `explain`, `keystone`, `help`, `legal`, `tip`, `autostart`, `filewatch` | ~2.4k | ~1.4k | skimmed (response-size limits, URLs) |
| `agent/internal/api/dashboard/index.html` | 2,851 | – | API calls, polling and action wiring traced; CSS/markup not reviewed |
| `docs/`, `README.md`, `CLAUDE.md`, shipped `internal/help/*.md` | – | – | claims cross-checked against code |

**Tools run (read-only):** `go vet ./...` and `GOOS=windows go vet ./...` (clean). `gofmt -l` (empty). `staticcheck` linux+windows (clean). `govulncheck` linux+windows (1 finding, R-08). `deadcode` (x/tools v0.39.0, linux view only, since its windows load fails on this box). `go test -count=1 ./...` (all 24 packages ok, 4.7 s). I built the agent and ran it in **replay mode** in the scratchpad to reproduce R-01 and R-05. Query timings for R-06 and R-07 were measured in CPython's sqlite3 against the real `schema.sql` with 200k synthetic rows.

**Not executable here:** everything under `//go:build windows` (ETW, Authenticode, taskkill/netsh/icacls, registry). All runtime claims about those paths come from reading the code and are marked as such.

**Excluded:** `go.sum`; `testdata/traces`; the 75 KB `docs/plans/2026-07-27-cross-platform-assessment.md` (a record of a settled no-go decision).

## Recommended changes (prioritised)

| ID | Title | Lens | Severity | Effort | Should/Could |
|---|---|---|---|---|---|
| R-01 | API token is served unauthenticated at `GET /`; Known Limitations overclaims; Windows file "0600 ACL" claim is false | bug (security) | High | M | Should |
| R-02 | Elevated agent executes undo/actions from a user-writable DB; undo validation allows arbitrary file destination and HKLM Winlogon/IFEO writes | bug (security) | High | M | Should |
| R-03 | Connection-path alerts (critical C2 / exfil, high beaconing) never deliver a toast | bug | High | S | Should |
| R-04 | "Stop program" kills by a stored, possibly recycled PID; drill alerts offer a real kill | bug (security) | Med | S | Should |
| R-05 | "Always allow" silently fails for credential-theft and persistence alerts (reproduced) | bug | Med | S | Should |
| R-06 | Per-network-event hot path: unindexable `COUNT(*)` first-contact query, story built then discarded, redundant id lookup | perf | Med | S | Should |
| R-07 | Dashboard 5 s poll: full scans + sort, reads every story blob to compute a boolean, no `last_seen` index, unbounded `limit` | perf | Med | S | Should |
| R-08 | GO-2026-6859 (net/http) reachable; fixed in go1.26.11; published 0.1.8-pre is affected | bug (security) | Med | S | Should |
| R-09 | First-contact check uses a different image string than the stored row (svchost service labels), so FirstContact is always true for service hosts | bug | Low | S | Should |
| R-10 | Authenticode lookup spawns PowerShell synchronously on the ingest goroutine; trust cache keyed by path only, never invalidated | perf / bug | Med | M | Should |
| R-11 | In-project duplication: 3× `system32()`, dead `platform.ServiceLabel` = `labelWithServices`, twin `download()`/`fresh()`, duplicated DTO mapping and alert-persist blocks | reuse / slop | Low | S | Should |
| R-12 | Dead / test-only code, incl. the `/api/talkers` endpoint | slop | Low | S | Should |
| R-13 | Doc drift: nonexistent `--no-serve` flag, misplaced doc comment, CLAUDE.md "signed, hot-loaded" packs | slop | Low | S | Should |
| R-14 | Smaller inefficiencies: `AlertsForImage` filters 500 rows in Go; resolver caches failures forever, so the backfill loop scans uselessly; unbounded downloads | perf | Low | S | Could |
| R-15 | Dormant CI workflow was deleted; portfolio rule says keep it as the Gate 3 spec | slop (process) | Low | S | Could |
| R-16 | No schema migration mechanism (fine so far; first column change will break upgrades) | incomplete | Low | M | Could |

## Findings in detail

### R-01 — The API token is given away by `GET /`; the shipped security claims built on it are false

**What's there.**
- `agent/internal/api/server.go:965-997` (`dashboardHandler`) substitutes the live token into `index.html` (`server.go:976`).
- `/` is deliberately outside the token check (`server.go:224-227`, "the dashboard shell itself is exempt"). Only the Host header is checked (`requireLocalHost`, `server.go:240-258`).
- So any local client can read the token and then call every `/api/*` route. Reproduced against a replay-mode build of `cb4eee6`:

```
--- unauth GET /:            TOKEN = "9745b3d3…     (prefix of the token in the page)
--- file token prefix:       9745b3d3               (agent's api-token file)
--- /api/settings with scraped token: {"dedupSeconds":300,…}   (200)
--- no token:                401
```

The shipped document `agent/internal/help/known-limitations.md:17-23` (compiled into the binary and shown in the dashboard) promises that the token stops:
- "other user accounts on a shared machine". False: loopback is shared across Windows sessions, and another user just GETs `/`.
- "opportunistic malware that probes fixed local ports". False: one GET of `/` on the fixed port 8973 is all it takes.

The `auth.go:28-33` comment makes the same claims.

Separately, `auth.go:63-64` says "0600: on Windows this maps to an ACL granting only the owner". That is not how Go behaves: on Windows `os.WriteFile`/`OpenFile` use only the 0200 bit, to set or clear the read-only attribute. The file inherits its directory's ACL. The same assumption is behind "Owner-only" on the Keystone export (`cmd/nitewatch/main.go:177-179`).

**Why it matters.** This is a security product. It publishes a security boundary it does not have, and the token is the only thing between a local process and the remediation endpoints (kill, quarantine, firewall, registry; see R-02).

**Proposed change.**
1. Stop injecting the token into the served HTML. Keep it out of anything an unauthenticated request can fetch. Simplest change that keeps double-click UX: `main.go:239-243` opens `http://127.0.0.1:8973/#t=<token>`. A URL fragment is never sent to the server and never appears in Referer. The page copies it into `sessionStorage`, strips the hash with `history.replaceState`, and sends the header as today. A user who opens the bare URL gets a "launch from NiteWatch (or paste the link printed in the console)" panel. The alternative is a one-time bootstrap nonce exchanged for an `HttpOnly; SameSite=Strict` cookie.
2. Give the token file a real owner-only DACL on Windows (`golang.org/x/sys/windows` `SetNamedSecurityInfo` with a protected DACL: owner + SYSTEM). Do the same for the export file, or drop the "owner-only" comment.
3. Rewrite `known-limitations.md` §"The local API cannot authenticate a local process" and the `auth.go` header to say what actually holds after the fix.

**Risks.** Bookmarked dashboards stop working until relaunched from the agent; say so in the release notes. The long-term fix (named pipe with an ACL, already noted in the doc) is unchanged.

**Verify.** Add an `api` test: `GET /` with a token configured must not contain the 64-hex token. Re-run the curl sequence above: the first line must come back empty.

### R-02 — The elevated agent trusts action and undo records from a database the user can write

**What's there.** The agent must run elevated (ETW). Its ledger, token and `quarantine\` folder all live next to the exe (`main.go:58-66`, `main.go:217`), which is usually a user-writable folder such as Downloads. The shipped doc admits the database is tamperable (`known-limitations.md:43-48`) but asserts: "Undo records are now structurally validated so a tampered record cannot become an arbitrary write." The validation in `agent/internal/respond/respond.go:277-330` does not support that:

- **QuarantineFile undo** (`respond.go:291-304`): `from` must be under the quarantine folder, which is itself user-writable. `to` is checked only for `..` segments, so `C:\Windows\System32\anything.dll` passes. `exec_windows.go:142-160` (`restore`) then strips the deny ACE, creates the parent directory and renames the file there, all as Administrator.
- **RemoveAutostart "file" undo** (`respond.go:307-311`): `to` is not checked at all. `exec_windows.go:206-212` renames `from` to it.
- **RemoveAutostart "registry" undo** (`respond.go:312-322`): any value name and any string value may be written under the allowed prefixes. Those prefixes (`respond.go:334-343`) include `HKLM\…\Winlogon` (e.g. `Userinit`, `Shell`) and `HKLM\…\Image File Execution Options` (e.g. `<exe>\Debugger`). `exec_windows.go:223` writes it with `SetStringValue`.
- **Execute path:** `handleRunAction` (`server.go:871-923`) re-derives the action from the stored alert's evidence, which is right against a hand-crafted request. But the alert row comes from the same writable DB, so a forged alert lets the agent delete HKLM autostart values, quarantine any non-system file, or `taskkill /T /F` any PID.

Combined with R-01 (the token is free), a medium-integrity process running as the user can insert a row into `actions` or `alerts` and then POST to `/api/actions/undo` or `/api/actions/run`. The agent then performs registry writes and file moves with admin rights. That is a same-user-to-admin escalation.

**Not executed:** the Windows half could not be run on this box. The validation gaps are verified by reading `ValidateUndo` and the executor.

**Proposed change** (in order of value):
1. **Authenticate the records.** At startup, generate or load a per-install HMAC key held outside the ledger: DPAPI-protected at machine scope, or kept in memory only, with undo limited to the current run. MAC `(kind, params, undo)` when an action is recorded and the rendered evidence when an alert is recorded. Refuse to run or undo anything whose MAC does not verify. This turns "user-writable DB" into "user can delete history" rather than "user can direct the elevated process".
2. **Tighten `ValidateUndo` regardless.** For QuarantineFile, require `to` to equal the path recorded in the matching action's `Params["path"]`, and refuse `%SystemRoot%`/`%ProgramFiles%` targets. Validate `to` for the startup-file undo the same way. For registry undo, refuse Winlogon/IFEO restores unless `name` matches the alert's `EntryName` and `value` matches the alert's recorded `Target`, or drop those two prefixes from the restorable set.
3. Fix the `known-limitations.md:45-48` claim.
4. Moving the DB to `%ProgramData%` with an ACL (already the installer plan, ORCHESTRATOR roadmap item 2) closes most of this, but the HMAC still matters for the portable exe.

**Risks.** Existing action rows have no MAC, so undo of pre-upgrade actions would be refused. That is acceptable for a pre-release, and should be stated.

**Verify.** Add unit tests in `respond` for each rejected shape: System32 destination, unchecked startup `to`, Winlogon value mismatch. Then a VM test: forge a row with `sqlite3` and confirm `/api/actions/undo` refuses it.

### R-03 — Network alerts never raise a toast

**What's there.** There are three alert-persisting paths in `agent/internal/collector/collector.go`:
- `runDetections` (connections), `collector.go:392-414`: writes the alert and logs it. **No `Notify.Deliver`.**
- `reportFile`, `collector.go:611-627`: calls `c.opts.Notify.Deliver`.
- `reportAutostart`, `collector.go:717-735`: calls `c.opts.Notify.Deliver`.

`git log -G'Notify.Deliver'` shows the call was added to the autostart path in `79c57e8` ("toast notifications and one-click remediation") and to the file path in `fcd8ee8`. It was never added to the connection path. As a result, these alerts reach only the dashboard:
- `c2-feed-flagged-connection` (critical, `rules/c2.yaml:9-11`)
- `c2-exfil-after-secret-read` (critical, `c2.yaml:86-88`)
- `c2-beaconing` (high, `c2.yaml:107-109`)

The design doc says Critical = takeover toast and High = actionable toast (`docs/plans/2026-07-24-nitewatch-design.md:145-146`). The "Test me" drill does not catch this because it calls the engine directly, not the collector.

**Proposed change.** Extract one helper in the collector, `recordAndNotify(d detect.Detection, anchor int64, at time.Time, fields map[string]any) bool`. It renders the title once, records the alert, logs it, and delivers the toast. Use it from all three paths, which also removes about 40 lines of triplicated code (see R-11). The notify gate already does cooldown and burst caps (`notify/notify.go:74-105`), so this cannot flood.

**Verify.** Add a collector test with a fake `notify.Notifier`: replay `testdata/traces/malicious.jsonl` with a feed hit and assert one `Notify` call. On the VM, the owed Gate 5 smoke test item "a feed-flagged connection → toast" will exercise it for real.

### R-04 — "Stop program" kills whatever currently holds a stored PID

**What's there.** `respond.Suggest` puts the alert's `PID` evidence into the action (`respond.go:69-77`, `91-99`, `113-121`). `exec_windows.go:59-70` runs `taskkill /PID <pid> /T /F` with no check that the process at that PID is still the alert's image. An alert can sit unread for hours, and this project has repeatedly been bitten by Windows PID reuse (ORCHESTRATOR history: the occupancy rewrite and the recycled file handles). Killing the wrong process tree is the "cannot be undone" button.

There is also a specific case in the self-test. Drill alerts get remediation buttons, because `handleActions` (`server.go:849-866`) and `handleRunAction` do not check `Evidence["Drill"]`. The ransomware backup-destruction drill uses PID `424244` (`selftest/selftest.go:384`). That is a multiple of 4, so it is a valid Windows PID, and pressing "Stop not-a-real-program.exe now" on the drill would kill whatever real process tree holds 424244.

**Proposed change.**
- In `kill`, read `platform.ProcessImage(pid)` and refuse unless it equals `Params["image"]` (case-insensitive), with a message like "that program has already exited".
- Better still, store the occupant's start time or `StartKey` in the evidence and compare that.
- Refuse all actions for alerts whose evidence has `Drill: true`, both in `handleActions` (report `available:false`) and in `handleRunAction`.

**Verify.** Add a unit test for the drill refusal (cross-platform, in `api`). The image check needs the VM.

### R-05 — "Always allow" silently does nothing for credential-theft and persistence alerts

**What's there.** `handleAllowAlert` (`server.go:818-846`) builds the allow key from `Evidence["ImagePath"]` and `Evidence["Destination"]`. The suppressor then checks a key built differently per path:
- **File alerts:** `reportFile` checks with `Domain: subj.Path` (`collector.go:596-600`), so the check uses the secret's path as `dest`. File evidence has no `Destination` (`detect/files.go:64-71`), so the stored key ends in `|`. For credential reads (Path set) the keys never match. For ransomware bursts Path is empty, so those happen to work.
- **Persistence alerts:** evidence has neither `ImagePath` nor `Destination` (`detect/persistence.go:55-65`). The check uses image = target and dest = Location (`collector.go:708-712`). They never match.

**Reproduced** with a two-line crafted trace in which `helper.exe` reads Chrome's `Login Data`. The run-1 alert was allowed via the API, and run 2 (same program, new PID) used the same DB:

```
allowlist: [('credential-theft|c:\\users\\kevin\\downloads\\helper.exe|',)]
alerts:    [(1,'credential-theft',-301,'acknowledged'), (2,'credential-theft',-305,'new')]
```

The dashboard offers the button on every alert (`index.html:2656`), and the README lists "per-program/destination always allow" as a feature.

**Proposed change.** Compute the suppression key once, where the detection is checked, and store it in the evidence (e.g. `fields["AllowKey"] = detect.Key(rule, image, dest)`). `handleAllowAlert` then uses `AllowKey` when present and falls back to today's derivation for old alerts. That makes allow and check use the same key by construction.

**Verify.** Turn the repro into a collector or api test: allow alert 1, ingest the second trace, and expect no second alert.

### R-06 — Per-network-event hot path does avoidable SQL and JSON work

**What's there.** `ingest` runs for **every** Kernel-Network event. The provider is subscribed unfiltered (`source/etw_windows.go:91-97`, "Volume is handled by flow de-duplication"), so this is roughly per packet. Before dedup it runs:

1. `IsNewDestination` (`ledger/ledger.go:400-411`): `SELECT COUNT(*) … WHERE image = ? AND (domain = ? OR (domain IS NULL AND remote_ip = ?))`. The `OR` stops either index from being used beyond the `image` prefix, so it counts every row the program ever made. At 200k rows (46 images, Chrome-heavy) it took **14.6 ms**. Two `EXISTS` sub-queries give the same answer in **~0.0 ms**.
2. Builds the story (`StoryFor`, `ContextAt`, `Narrate`, `json.Marshal`; `collector.go:298-313`) every time. When the event dedups into an existing row, the `UPDATE` keeps the old story (`story = COALESCE(NULLIF(story,''), ?)`, `ledger.go:190`), so the work is thrown away for every packet after the first.
3. `RecordConnectionDedup`: a SELECT plus an UPDATE or INSERT.
4. `runDetections` → `ConnectionID` (`ledger.go:367-377`): a third SELECT to find the row id that step 3 already knew.

The collector is single-threaded, so ~15+ ms per event caps ingest at well under 100 events/s on a mature ledger. ETW real-time sessions drop events when the consumer lags.

**Proposed change.**
- Rewrite `IsNewDestination` as `SELECT EXISTS(SELECT 1 … image=? AND domain=?) OR EXISTS(SELECT 1 … image=? AND remote_ip=? AND domain IS NULL)`. The existing `idx_conn_image_domain` and `idx_conn_flow` cover both halves.
- Have `RecordConnectionDedup` return `(id int64, inserted bool, err error)`. Build the story lazily, only when inserting or when the existing row has none (a cheap `story IS NULL` column read in the dedup SELECT). Delete `ConnectionID` (its only caller is `collector.go:368`).
- Optionally, cache first-contact answers per `(image, dest)` in memory for the run.

**Verify.** Run the timing script in the scratchpad pattern, or `EXPLAIN QUERY PLAN` in a ledger test, asserting no `SCAN connections`. Collector tests must still pass. Add a benchmark for `ingest` over a 100k-row ledger.

### R-07 — The dashboard's 5-second poll scans the whole ledger and reads every story

**What's there.** `index.html:2821-2848` calls `/api/summary` and `/api/connections?limit=1000` every 5 s.
- `RecentConnections` (`ledger.go:222-236`) orders by `last_seen DESC`, and **no index exists on `last_seen`**. `idx_conn_ts` is on `ts`, which nothing orders or filters by (`schema.sql:20`). It also selects `story` for 1,000 rows (~1–3 KB each) only so `handleConnections` can compute `HasStory` (`server.go:299`).
- `Summarise` (`ledger.go:439-454`) is a full scan with two `COUNT(DISTINCT)`s.

Measured at 200k rows: RecentConnections **78.9 ms**, which drops to **1.6 ms** with a `last_seen` index and a boolean instead of the blob; Summarise **73.4 ms**.

Also unindexed: `Prune` (`last_seen < ?`, hourly), `UnnamedIPs` (every 10 s, 40 ms; `ledger.go:328`) and `SetDomainForIP` (`remote_ip = ?`, per resolved IP; `ledger.go:353`) — all `SCAN connections`.

`limit` is unbounded on `/api/connections` and `/api/alerts` (`server.go:283-288`, `744-749`): `?limit=100000000` loads every row and story into memory.

**Proposed change.**
- `schema.sql`: add `CREATE INDEX IF NOT EXISTS idx_conn_last_seen ON connections(last_seen)` and `idx_conn_remote_ip ON connections(remote_ip)`. Drop `idx_conn_ts` after a grep confirms no `ts`-only query.
- Add a `RecentConnectionsSummary` that selects `(story IS NOT NULL AND story <> '') AS has_story` instead of the blob, and use it in `handleConnections`.
- Clamp `limit` to e.g. 5000.
- Cache `Summarise` for ~30 s, or maintain counters.

**Verify.** `EXPLAIN QUERY PLAN` assertions in `ledger_test.go`. Before/after timing on a seeded DB.

### R-08 — New reachable stdlib vulnerability; Gate 6's clean scan is stale

**What's there.** `govulncheck ./...` (linux and windows) at `cb4eee6` reports **GO-2026-6859**, "HTTP/1 server crash due to MaxBytesReader header race in net/http". It is found in go1.26.10 and fixed in **go1.26.11**. It is reachable via `api.Server.ListenAndServe`, and `handleSettings` uses `http.MaxBytesReader` (`server.go:361`). The published `v0.1.8-pre` was built with go1.26.10, so it carries the same finding. ORCHESTRATOR.md's Gate 6 "No vulnerabilities found" was true on 2026-10-25 and is not true now. go1.26.11 is already downloadable on this box: the `deadcode` run auto-switched to it.

**Impact.** A crash of the local server. Because of R-01, any local process can reach `PUT /api/settings`, so in the worst case malware could take down the agent.

**Proposed change.** `toolchain go1.26.11` in `agent/go.mod`, then re-run govulncheck. A 0.1.9-pre release is Kevin's call. It would also carry R-01 to R-05.

### R-09 — First-contact lookup and the stored row use different image strings

**What's there.** `ingest` asks `IsNewDestination(imageFor(e, c), …)` (`collector.go:289`). `imageFor` resolves `e.Image → ImageAt(pid, time) → lookupImage` (`collector.go:418-426`). The row it then writes uses `e.Image → ImageFor(pid) → lookupImage`, **then rewrites service hosts** to `"Windows Update (svchost.exe)"` via `labelWithServices` (`collector.go:315-328`). Two consequences:
- For any PID in `serviceNames`, the first-contact query compares the raw `…\svchost.exe` path against rows stored under the label. It never matches, so `FirstContact` is always true for service hosts. The first-contact-gated rules (`foreign-first-contact`, `raw-ip-no-dns`, `unsigned-outbound`; `detect/engine.go:184-282`) can refire on every new row (every 5-minute dedup window) instead of once.
- The `imageFor` comment ("resolves the acting image the same way the ledger row does") is false.

This was verified by reading, not replayed: replay has no service table.

**Proposed change.** Resolve the display image once at the top of the network branch and use that one string for the first-contact check, the row, the suppressor, and `isSelf`. Use the time-aware `ImageAt` everywhere, consistent with the occupancy work.

### R-10 — Authenticode lookups block ingest, and cached trust never expires

**What's there.**
- `platform/signer_windows.go:47-66`: the first lookup per path runs `powershell.exe Get-AuthenticodeSignature` **synchronously**. Callers are on the collector goroutine (`collector.go:378`, `549`, `562`; `reportAutostart` `703`). A cold PowerShell start typically costs hundreds of ms (not measured here — Windows), and the first minutes after start meet many new binaries, so ingest stalls exactly when the seeded process table is being exercised.
- The cache is keyed by path only and never invalidated. A binary replaced in place, which is the classic trojanised-updater shape, keeps the old "Valid, signed by X" result for the rest of the run. `TrustedSigner` then suppresses its low/medium findings (`detect/suppress.go:184-186`).

**Proposed change.** Key the cache on `(path, size, mtime)`. Resolve asynchronously like `resolve.Resolver` does, with unknown treated as "not trusted", which is already the safe direction. Bound the cache (LRU, e.g. 2,048 entries).

### R-11 — Duplicated helpers inside the project

All verified by reading both copies:
- **Three `system32()` implementations:** `platform/signer_windows.go:106`, `notify/toast_windows.go:90` (variadic) and `respond/exec_windows.go:261` (single name). Move one into `internal/platform` (it is already the Windows-helpers package) and import it.
- **`platform.ServiceLabel`** (`platform/proctable_windows.go:132-147`) is byte-for-byte the same as `collector.labelWithServices` (`collector.go:465-475`) and has no callers (it is also stubbed in `proctable_stub.go:20-21`). Delete the platform one.
- **`intel/feeds.go:124-159` `fresh()` + `download()`** and **`recon/fetch.go` `fresh()` + `download()`** are the same temp-file-then-rename downloader (recon adds gunzip). Extract `internal/fetch.Download(ctx, url, dest, opts{gunzip, maxBytes})` and add a size cap (see R-14).
- **`connectionDTO` mapping** is written twice (`server.go:291-301` and `1037-1046`), as is **`alertDTO` mapping** (`server.go:756-768` and `1049-1060`). Add `toConnectionDTO(ledger.Connection)` and `toAlertDTO(ledger.Alert)`.
- **The alert persist + log + notify block** appears three times in `collector.go`. Fold it into one helper (that is the fix for R-03).

### R-12 — Dead and test-only code

Found by `deadcode` (linux view) and confirmed by grepping non-test callers with two patterns each:
- **Unused HTTP route:** `/api/talkers` (`server.go:169`, `309-328`). Only tests call it (`server_test.go:62`, `251`). The dashboard computes "Processes" from `/api/summary` (`index.html:1841`). It also loads 1,000 full rows, stories included, to count images. Delete it with its test lines.
- **Unused functions:**
  - `collector.New` (`collector.go:107`)
  - `Suppressor.Allow` (`detect/suppress.go:110`)
  - `explain.ForTerm` and `explain.Count` (`explain/explain.go:178`, `187`)
  - `Graph.Poset` and `Graph.KnownNameFor` (`graph/graph.go:41`, `75`)
  - `help.KnownLimitations`, `help.Roadmap` and `help.Title` (`help/help.go:55-62`)
  - `intel.Store.Loaded` (`intel/intel.go:75`)
  - `recon.DB.Loaded` and `recon.Info.Known` (`recon/recon.go:69`, `37`)
  - `LocalNets.Add` (`resolve/localnets.go:79`)
  - `rules.Set.All` and `rules.Set.Len` (`rules/pack.go:190-193`)
  - `selftest.Describe` (`selftest/selftest.go:494`)
  - `platform.ServiceLabel` (R-11)

  For each one, delete it, or keep it only if a test is using it as a fixture helper, in which case move it to a `_test.go` file.
- **Not dead, despite deadcode:** `source/etw_parse.go` and `source/namecache.go` look unreachable on linux but are called from `etw_windows.go`. Leave them.

### R-13 — Documentation drift

- `cmd/nitewatch/main.go:10` documents `nitewatch --no-serve --replay <file>`. **That flag does not exist**: running it prints usage and exits, which I hit while reproducing. The real form is `-serve=false`. `cmd/nitewatch` has no tests, which is how this survives.
- `api/server.go:115-116`: the `WithSettings` doc comment sits on `WithBuild`, and `WithSettings` (`:122`) has none.
- `CLAUDE.md:33` says rule packs are "signed … hot-loaded". `rules/pack.go:11-18` and `known-limitations.md:63-68` correctly say neither is implemented. Fix CLAUDE.md.
- `known-limitations.md`: header "Last updated: 2026-07-26", plus the false claims in R-01 and R-02. `README.md` "per-program/destination always allow" (R-05).

### R-14 — Smaller inefficiencies

- `ledger.AlertsForImage` (`ledger.go:309-324`) loads the 500 most recent alerts, JSON-decodes each evidence blob, and filters in Go. Alerts older than the newest 500 vanish from the process view. Either add an `image` column to `alerts` (indexed) or use `json_extract(evidence,'$.ImagePath') = ?`.
- `resolve.Resolver` (`resolve/resolve.go:21-37`) caches `""` for a failed PTR lookup forever and has no size bound. Because of the cached failures, `backfillNames` (`collector.go:634-658`) re-runs the unindexed `UnnamedIPs` scan every 10 s for IPs that will never resolve. Add a TTL for negative entries (e.g. 1 h) and an LRU bound.
- `intel.download` and `recon.download` copy response bodies without a size limit. recon gunzips without a limit, so a bad mirror or gzip bomb can fill the disk. Wrap the body in `io.LimitReader`, e.g. 64 MB for feeds and 512 MB decompressed for ip2asn.

### R-15 — The dormant workflow file was deleted

`.github/workflows/` does not exist. It was removed in PR #4 ("fix: patch Go toolchain to 1.25.12; delete no-Actions-policy-violating CI workflow", `00b0315`). The portfolio Gate 3 rule asks the opposite: keep dormant workflow files accurate as the specification of "the full suite". Restore `agent.yml` covering vet (linux+windows), `test -race`, staticcheck, govulncheck and a windows build, with Actions left disabled. This is a judgement call against what that PR decided, so it is marked Could.

### R-16 — No schema migration mechanism

The ledger uses only `CREATE TABLE IF NOT EXISTS` (`ledger.go:105-120`, `schema.sql`). I checked: `schema.sql` is identical between `v0.1.0-pre` and `v0.1.8-pre`, so no upgrade has broken yet. But the first added column will make every INSERT on an upgraded DB fail ("recording connections is FAILING"). Add `PRAGMA user_version`-based migrations before the installer and `%ProgramData%` move, which will be the first schema-touching work.

## Cross-project reuse

Context: NiteWatch and Checkride both build GoRapide posets from Windows telemetry and **must never be merged**. I compared `~/Projects/checkride` (read-only) package by package. A normalised line-overlap scan (non-comment lines over 35 chars) between the two Go trees found **7 shared lines in total, all boilerplate**. There is **no copied code to have drifted**: the "shared engine" is the GoRapide dependency plus shared lessons, not shared source.

| # | Item | Recommendation | Confidence |
|---|---|---|---|
| X-1 | **Checkride resolves `reg.exe` through `%PATH%`** (`checkride/internal/state/collector_windows.go:55`, `exec.Command("reg", …)`). NiteWatch closed this exact PATH-hijack class with `system32()` (`platform/signer_windows.go:102-112`, and its known-limitations doc). | **Keep separate; port the fix** into checkride: an absolute `%SystemRoot%\System32\reg.exe`. A shared module for a 10-line helper is not worth a cross-repo dependency. Revisit only if a third Windows Go product appears; then a tiny `winexec` module (absolute System32 resolution + env-passed arguments) is the natural extraction. | High (finding); Medium (no-module call) |
| X-2 | **Poset generation rotation is implemented twice**: `nitewatch/agent/internal/graph/window.go` (event-count bounded, 50k; PID-keyed live map; carries DNS answers across) vs `checkride/internal/model/generation.go` (interval-based; GUID-keyed; carries `GenerationStats` shortfall). | **Keep deliberately separate.** The semantics differ on purpose (consumer PID+StartKey occupancy vs enterprise Sysmon ProcessGuid). A shared module would force one keying model on both. What should be shared is the recorded constraint "gorapide posets are add-only", which both repos already document. | Medium |
| X-3 | **GoRapide version**: both `go.mod`s pin `github.com/ShaneDolphin/gorapide v0.0.0-20260712235008-08752c7ea938`. No drift. | Bump them together, and re-run both suites, because both depend on add-only and `AddEventWithCause` behaviour. | High |
| X-4 | **Build identity**: NiteWatch's `internal/buildinfo` (VCS stamping from `debug.ReadBuildInfo`, plus the git-worktree mis-stamp gotcha) has no Checkride equivalent. Checkride has no `ReadBuildInfo` anywhere. | Copy the ~80-line package into Checkride when it starts shipping binaries. Not a shared module. | Low–Medium |
| X-5 | **Licensing constraint on any future shared module**: NiteWatch is GPL-3.0-or-later (inherited from `golang-etw`, SPDX headers on every file). Checkride has no LICENSE file and no SPDX headers. | Before extracting anything shared, decide its licence. Threat Tape owns both copyrights, so Kevin can license his own code freely, but anything that links `golang-etw` stays GPL. | High |
| X-6 | Keystone consumes NiteWatch's export (`internal/keystone`, `docs/story-format.md`). | Already tracked as the open "How should Keystone receive NiteWatch data" decision in ORCHESTRATOR.md. Nothing new. | – |

No reuse with `edgar` (no Windows signer, buildinfo, RDAP or ASN code found by grep) or with `recon` (its RDAP/ASN logic is Python).

## Things that look wrong but are fine

- **`etw_parse.go` / `namecache.go` flagged unreachable by `deadcode`.** That is the linux view only; `etw_windows.go` calls them.
- **The ledger schema has no migrations.** It is byte-identical across all nine release tags, so no user has an incompatible DB yet (the risk is future, R-16).
- **Concurrency between the HTTP goroutines (self-test, allow) and the collector.** The beacon and exfil trackers, suppressor, notify gate, settings, intel and recon stores all hold their own mutexes.
- **PowerShell invocations.** Paths travel through environment variables and are never interpolated (`signer_windows.go:66-73`, `identity_windows.go:96-104`). Helper binaries use absolute System32 paths.
- **DNS rebinding.** The Host-header check (`server.go:240-258`) and CSRF protection (custom header + Origin check, `guardMutation` `server.go:776-797`) are correct for browser attackers. R-01 concerns non-browser local clients.
- **`SetMaxOpenConns(4)` with WAL.** The comment's reasoning is right (`ledger.go:97-104`); a pool of 1 would serialise reads behind writes.
- **`handleRunAction` re-derives the action from the stored alert** rather than trusting the request. That is the right design, and the gap is the DB's trust level (R-02), not this logic.
- **`intel` / `recon` / `rdap` / `vt` use HTTPS**, and `rdap`/`vt` cap response bodies (`LimitReader` 1 MB / 4 MB).
- **Shared-text duplication with Checkride:** effectively none, so there is no drift to reconcile.
- **Test suite.** 24 packages, about 5 s, no flakes seen in one run. `platform` has no tests because it is all Windows-only code with stubs.

## Suggested sequencing

1. **PR "local API trust"**: R-01 (token bootstrap + DACL), R-02 (HMAC on actions/alerts + tightened `ValidateUndo`), R-04 (PID/image check, refuse drill actions), and the matching `known-limitations.md` and `auth.go` rewrites. These belong together because the shipped document has to be rewritten once, around the final model. The Windows half needs the VM to verify. Land it with cross-platform unit tests and mark the VM checks as owed.
2. **PR "alert wiring"**: R-03 (single `recordAndNotify` helper, which also removes the triplicated block from R-11), R-05 (`AllowKey` in evidence), R-09 (one image resolution). These are cross-platform and testable with replay traces today.
3. **PR "ledger performance"**: R-06 and R-07 (indexes, `EXISTS`, lazy story, id returned from the dedup write, `has_story` boolean, `limit` clamp), plus R-14's `AlertsForImage` and resolver TTL. Include `EXPLAIN QUERY PLAN` tests.
4. **PR "toolchain"**: R-08, go1.26.11. Then Kevin decides whether 0.1.9-pre ships with 1–4 (that would refresh Gate 6).
5. **PR "cleanup"**: R-11 (remainder), R-12, R-13, and R-15 if Kevin agrees.
6. **With the installer work**: R-10 (async/invalidated signer cache) and R-16 (`user_version` migrations), since the `%ProgramData%` move is the first schema- and service-touching change.
