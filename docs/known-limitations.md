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
- **Beaconing detection** (regular-interval C2 callbacks) is described in the
  P2 plan but not built. The ledger records what it needs; the detector does
  not exist.

### Structural gaps

- **Process attribution keys on PID.** Windows recycles PIDs. The cache is
  cleared on process exit, but a missed exit event can still misattribute a
  connection. Sysmon's ProcessGuid would fix this properly.
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
- **Windows only.** macOS and Linux would need entirely different sensors.

---

## Data and privacy

- **Nothing about the user's machine leaves it.** Feeds and the ownership
  dataset are downloaded whole; no per-address query is made to a third party.
  The only outbound traffic is fetching those public files.
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
- **Feed licensing is not settled.** See `docs/feed-licensing.md`; several
  high-quality sources are unusable commercially without written permission,
  and caching feed data on customer machines is redistribution rather than use.
- **Never validated over a long real-world session.** The false-positive rate
  during ordinary use is unmeasured, and it is the number that decides whether
  the tuning is right.
