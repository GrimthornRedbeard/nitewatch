# NiteWatch — Known Limitations

**Last updated:** 2026-07-26

What this software does **not** do, and where its guarantees stop. Kept because
a security product that overstates its coverage is worse than one that admits
gaps: a user who believes they are protected takes risks they otherwise would
not.

---

## Security boundaries

### The local API cannot authenticate a local process

The dashboard is served over loopback HTTP. Any process on the machine can open
a loopback socket, and HTTP carries no identity for the caller. The API token
(stored owner-readable beside the agent) stops:

- other user accounts on a shared machine,
- opportunistic malware that probes fixed local ports without knowing about
  NiteWatch,
- a web page that got past the Host check, since it cannot read a local file.

It does **not** stop a process running as the same user that reads the token
file — and such a process could read the ledger database directly anyway.

**Proper fix:** a named pipe with an ACL, which carries caller identity at the
OS level. Not yet implemented.

### The agent runs elevated and is therefore a target

ETW requires Administrator. Every input reaching an elevated process is attack
surface. Two classes have been closed:

- **Command injection** — all data passed to PowerShell now travels through
  environment variables, never interpolated into script text. Escaping quotes
  was insufficient: PowerShell's tokenizer also accepts U+2018, U+2019, U+201A
  and U+201B as string delimiters.
- **PATH hijacking** — helper binaries (powershell, taskkill, netsh, icacls)
  are invoked by absolute `%SystemRoot%\System32` path.

**Still open:** the agent's own database and token live beside the executable.
If that is a user-writable folder (a Downloads directory, say), a same-user
attacker can tamper with them. Undo records are now structurally validated so
a tampered record cannot become an arbitrary write, but the DB should live in
`%ProgramData%\NiteWatch` with a restrictive ACL. **That is an installer
concern and the installer does not exist yet.**

### Detection can be evaded by anything that knows how it works

Every threshold in this product is documented in the source. An attacker who
reads it can stay under them: encrypt fewer than 40 files a minute, spread work
across processes, avoid the watched autostart keys. NiteWatch raises the cost of
commodity malware; it is not a defence against someone targeting *you*
specifically.

---

## Detection coverage

### Not implemented, despite appearing in the design

- **Rule packs are not signed.** Shipped packs are embedded in the binary and
  inherit its integrity; `--rules` loads unsigned YAML from disk and is a
  development affordance, not an update channel. Signing must land before packs
  ship separately.
- **Rule packs are not hot-loaded.** They are read once at startup.
- **Beaconing detection is built but unproven in the field.** `c2-beaconing`
  fires on coefficient-of-variation regularity after 15 samples, a threshold
  set by measurement against synthetic irregular traffic (8 samples gave 8 false
  alarms per 300 sequences; 15 gave none). It has never run against a real
  machine for a week, and deliberately jittered C2 will evade it.

### Structural gaps

- **Process attribution keys on PID, and this has been seen to go wrong.**
  Windows recycles PIDs, and Chromium-based applications churn through
  short-lived children faster than anything else on a desktop. A live machine
  produced three CRITICAL alerts for one file operation — "System", "brave.exe"
  and "claude.exe" each blamed for reading the same password store — along with
  each browser credited with writing into the other's profile directory.

  Two of the three causes are now fixed: the kernel is excluded, and SQLite
  journal files are no longer treated as the database. The third is mitigated
  rather than solved — when an event carries an image that disagrees with the
  one recorded for its PID, that is proof of reuse and the stale mapping is
  dropped, so activity is not chained onto a stranger's history. Events that
  carry no image still cannot be checked this way.

  **Sysmon's ProcessGuid, or the process start time, would fix this properly.**
  Until then, treat the acting program on a file alert as probable rather than
  certain, and check "What led to this" — if the chain looks like it belongs to
  a different program than the one named, it probably does.
- **No command lines or file hashes.** Raw ETW `Kernel-Process` does not supply
  either, so no detector can key on them. This rules out a whole class of
  detection (living-off-the-land argument patterns) that Sysmon would enable.
- **File events are filtered to user profiles.** Anything outside `\Users\` is
  discarded before analysis for volume reasons, so ransomware confined to, say,
  a data drive would be missed.
- **The causal window is bounded.** Poset generations rotate; only live process
  lineage is re-seeded. A connection arriving just after a rotation can lose its
  DNS association, which currently costs a false "connected without a lookup"
  finding. Alert stories are serialized at record time and are unaffected.
- **Signature checking shells out to PowerShell** — roughly 200ms per unique
  binary, cached thereafter. A burst of new executables briefly costs CPU.

### Deliberate non-goals

- **No kernel driver**, so nothing is blocked *before* it happens. NiteWatch
  observes and advises; it never sits in the path of an operation.
- **No automatic response.** Every remediation requires a click. A false
  positive that kills a needed process is worse than the malware being guessed
  at.
- **Windows only, and staying that way.** macOS and Linux were assessed on
  2026-07-27 and taken off the roadmap; NiteWatch is a Windows product. This is
  a settled scope decision, not a gap awaiting work. The short version: Linux
  cannot reliably attribute DNS lookups to a process — which is the headline
  feature — and has no code-signing equivalent, so the publisher allowlist that
  keeps the noise down has nothing to stand on; macOS needs an Apple
  entitlement that cannot be relied on. It would only be reconsidered if two
  things became true together: the Windows version ships signed and installable
  with a measured, acceptable false-positive rate — so the reason for waiting is
  gone — *and* the market case changes, meaning somebody specific asks for a
  platform, or the Linux per-process DNS gap is closed by something that does
  not exist today.

---

## Data and privacy

- **Nothing about the user's machine leaves it on its own.** Feeds and the
  ownership dataset are downloaded whole; nothing the agent does automatically
  makes a per-address query to a third party. All automatic outbound traffic is
  fetching those public files.
- **Registration lookup is a per-address query, and the user makes it.** The
  "who owns this?" button asks a public registry (via `rdap.org`) about one
  destination, which tells that registry the user is investigating it. It is the
  only per-address third-party query in the product. It never fires on ingest,
  on a timer, or as part of a page load — only on a click, and the button states
  what it will do before it is pressed. Results are cached for an hour so
  repeated clicks do not repeat the disclosure. The endpoint is POST-only and
  guarded like a state change, so a link or an image cannot trigger it. A test
  enumerates every route in the product and fails the build if any of them
  reaches a registry without a press, so this cannot quietly stop being true.
- **The VirusTotal check is a second per-file query, and the user makes it.**
  Off unless the user supplies their own API key, so the account doing the
  asking is theirs. It sends one SHA-256 — no file, no filename, no path,
  nothing else about the machine. Three honest caveats, all stated in the UI:
  for common software the query reveals essentially nothing; for a file that
  exists nowhere else the hash is close to an identifier; and VirusTotal's paid
  tiers let customers see who looks up hashes they care about, so in a targeted
  intrusion querying an implant can tip off the intruder. Never automatic;
  verified by a test that watches an idle dashboard make zero such calls.
- **Engine counts are evidence, not proof.** Zero detections is not safety —
  new malware is missed by everyone on its first day. One or two detections is
  usually a false positive. The wording around the numbers says so, and is
  under test, because a raw "3/72" misleads in both directions.

- **Registration data says who holds an address, not whether it is safe.** A
  recently registered domain is a useful signal, not a verdict; plenty of new
  domains are ordinary and plenty of malicious traffic runs on old, reputable
  infrastructure. The UI says so under every result.
- **Reverse DNS is an exception worth naming:** naming an address uses the
  user's configured resolver, which means their DNS provider sees lookups for
  addresses their machine contacted. Disable with the "Look up names" setting.
- **The ledger is not encrypted.** It records every program and destination on
  the machine — sensitive if the device is lost. Full-disk encryption is the
  answer; NiteWatch does not add its own.
- **Retention is enforced** (hourly prune). Unacknowledged alerts are never
  deleted: an unread warning is exactly what someone needs to find later.

---

## Operational

- **Unsigned binary.** SmartScreen and some AV will flag it, and the behaviour
  that makes it useful — reading kernel telemetry, opening a listener — looks
  like malware to heuristics. Code signing is unresolved.
- **No installer, no service, no auto-update.** It runs as a console
  application started by hand.
- **Feed licensing is not settled.** Several high-quality sources are unusable
  commercially without written permission, and caching feed data on customer
  machines is redistribution rather than use.
- **Never validated over a long real-world session.** The false-positive rate
  during ordinary use is unmeasured, and it is the number that decides whether
  the tuning is right.

---

## Something missing from this list?

This document is only as good as what is known. If NiteWatch did something not
described here — screamed about a program that was minding its own business,
stayed silent through something it should have caught, or simply fell over —
that is a gap in this page as much as in the code.

**threattape@gmail.com.** What it said, and what the computer was actually
doing at the time. That second part is the one that makes a report fixable.
