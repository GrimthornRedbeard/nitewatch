# NiteWatch — Linux and macOS Port Assessment

**Date:** 2026-07-27
**Status:** Assessment for decision. No implementation proposed or begun.
**Question asked:** what would it take to build Linux and/or macOS versions of NiteWatch,
and should we?

---

## Executive summary

**Recommendation: neither, yet.** Ship Windows first.

NiteWatch's code is more portable than it looks. Roughly 85% of it already compiles
and passes its tests on Linux and macOS today, untouched — the causal graph, the
connection ledger, the detection engine, the threat-intel matching, the dashboard,
the API. Only about 1,300 lines are locked to Windows behind build tags. On the face
of it, a port looks like "write a new sensor and you're done."

That is not what the code says. Two things leak out of the Windows sensor and into
the heart of the product:

1. **The trust model.** NiteWatch decides what *not* to warn you about by checking
   who digitally signed a program. Windows has that (Authenticode). macOS has an
   equivalent. **Linux has nothing equivalent at all.** The noise-control layer —
   which the design doc itself calls "make-or-break" — would be inert on Linux, and
   one shipped rule would fire on essentially every program on the machine. Fixing
   this is a research problem, not a porting task.
2. **The persistence model.** "Something set itself to start automatically" is a
   Windows registry concept end to end — the event type, the scanner, the four
   detectors, the four written alerts, the removal action and its undo safety check.
   On Linux and macOS this is not a translation, it is a rewrite through six layers.

On top of that, each platform has a specific obstacle:

- **Linux.** The technology works. eBPF gives us process lineage and
  process-attributed network connections at least as well as Windows ETW does, in
  pure Go, without a kernel module. But *per-process DNS visibility — the feature the
  product is built around* ("the thing netstat can never tell you") — is not
  reliably obtainable on Linux, and DNS-over-HTTPS is closing the remaining gaps.
  And the market is roughly 4% of desktops, skewed heavily technical, already served
  by free tools (OpenSnitch, Portmaster) that do the connection-monitoring half.
- **macOS.** The good sensor (EndpointSecurity) needs an entitlement Apple grants
  case by case and can decline, with **no published criteria and no way to estimate
  the odds in advance** — Apple's own developer-support engineer answers the "what
  are my chances" question with "suck it and see." Reported waits run from three
  months to a year with no reply, and rejections come as boilerplate with no reason
  given. There are documented cases of companies granted *development* access and
  then denied *distribution* access, which is a project you can finish and then
  cannot ship, with no enterprise fallback because macOS has no internal-distribution
  channel. And Objective-See already gives Mac users free tools covering all four of
  our detection areas.

  Two findings make macOS *less* bad than it first looks, and both are in Part 3: a
  content filter (`NEFilterDataProvider`) needs **no approval at all** and delivers
  the connection ledger with real process attribution; and `eslogger`, an
  Apple-signed tool shipped in macOS since Ventura, streams real EndpointSecurity
  events on a stock machine with no entitlement — enough for a working prototype
  before ever asking Apple for anything.

Meanwhile the Windows product — the one with 56% of the market and a working
sensor — is **unsigned, has no installer, runs as a hand-started console
application, has an unmeasured false-positive rate, and has an unresolved
threat-feed licensing question sitting with counsel.** Every one of those is a
launch blocker. None of them get easier by adding platforms; all of them get harder,
because the second platform doubles the surface that each fix has to be applied to.

The strongest argument for breadth is that porting pressure would force the
Windows-specific assumptions out of the core, which would be good engineering. That
is true, and it is not worth 5 to 7 months to buy.

**If a port is greenlit anyway, Linux first, macOS second** — Linux is cheaper, has
no external gatekeeper, and its blockers are ours to solve. Rough cost: **Linux 17–23
engineer-weeks, macOS 21–29 engineer-weeks** and an architecture change, *conditional
on an Apple approval we cannot forecast.*

---

## How this was checked

Everything in Part 1 was measured against the code in this repository on 2026-07-27,
not inferred. Line counts come from `wc -l`; build results from actually running the
compiler; leakage from grepping the untagged packages and then reading each hit.
Platform API facts in Parts 2 and 3 were checked against current documentation and
vendor/Apple sources, cited inline. Where a claim could not be confirmed it is marked
**unconfirmed** rather than smoothed over.

Baseline as measured:

```
go test ./...                                      all packages pass (Linux)
CGO_ENABLED=0 go build ./...                       ok (linux/amd64)
CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build    ok
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build    ok
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build   ok
```

The macOS cross-compile already succeeding is worth stating plainly: **the codebase
builds for macOS today.** It builds a binary that cannot see anything, because every
sensor call resolves to a `!windows` stub that returns an error — but the dependency
graph, including the pure-Go SQLite driver and the GoRapide causal engine, is already
portable. There is no dependency-level obstacle to either platform.

---

## Part 1 — The seam: what is actually Windows-bound

### 1.1 The measurement

13,201 lines of Go, of which 8,783 are non-test.

| Bucket | Non-test lines | Share |
|---|---|---|
| Platform-neutral (no build tag, no Windows assumptions) | ~6,100 | 69% |
| Behind `//go:build windows` | 1,320 | 15% |
| Untagged but Windows-shaped ("leakage") | ~1,275 | 15% |
| `!windows` stubs (thrown away by a port) | 89 | 1% |

The seven Windows-tagged files:

| File | Lines | What it does |
|---|---|---|
| `internal/source/etw_windows.go` | 479 | the ETW consumer — the actual sensor |
| `internal/respond/exec_windows.go` | 264 | kill / firewall / quarantine / registry undo |
| `internal/autostart/scan_windows.go` | 172 | registry + startup-folder snapshot |
| `internal/platform/proctable_windows.go` | 143 | process table + service names |
| `internal/platform/signer_windows.go` | 109 | Authenticode verification |
| `internal/notify/toast_windows.go` | 93 | Windows toast notifications |
| `internal/platform/platform_windows.go` | 60 | elevation check, image path, open browser |

Genuinely portable as-is, verified by reading: `graph` (778), `ledger` (636),
`detect/engine.go` and the C2 detectors, `intel` (379), `recon` (323), `rdap` (375),
`resolve` (182), `rules` (190), `settings` (177), `api` (815), `event` (82),
`source/replay.go` + `source/source.go`, `notify/notify.go`. The dashboard
(`internal/api/dashboard/index.html`, 891 lines) contains eight platform-specific
strings and is otherwise neutral.

The collector deserves specific credit: it takes `ProcessTable`, `SignerLookup` and
`ImageLookup` as **injected function values** in `collector.Options`, with comments
explicitly saying this keeps it platform-agnostic. That was the right call and it is
most of why the seam is as clean as it is.

### 1.2 The thesis under test

*"Is the sensor layer genuinely the only thing that needs replacing?"*

**No.** The sensor is the largest single piece but it is not the hard part, and it is
not the only thing. Windows leaks into the core in seven distinct ways. Two of them
are structural — they are not "find and replace the backslashes."

### 1.3 Structural leak #1: the trust model has no Linux equivalent

This is the most important finding in this document.

`internal/detect/suppress.go` is the noise-control spine. Its main gate:

```go
// A verified signature from a known publisher clears low/medium behavioural
// noise, which is most of what a normal desktop generates.
if TrustedSigner(subj.Event.Signer) && subj.Event.Signed && sev != "high" {
    return Verdict{true, "signed by a publisher you already trust"}
}
```

`trustedSigners` is a hand-curated map of 35 Authenticode publisher common names
(Microsoft Corporation, Google LLC, Valve Corp., …). It is consulted again in
`detect/persistence.go` (`detectTempLocation`), `detect/files.go`
(`detectCredentialTheft`), and it gates the shipped rule `c2-unsigned-first-contact`
whose entire premise is "this program is not digitally signed."

The code already knows about the problem. `internal/detect/engine.go:223`:

```go
// detectUnsignedOutbound fires when an unsigned program makes its first
// contact with a destination. Signature data is Windows-only; elsewhere Signed
// is false for everything, so the FirstContact gate keeps this quiet.
```

That comment is honest about the mechanism and optimistic about the consequence. On
Linux, `Signed` would be false for *every process on the machine* — `/usr/bin/curl`,
Firefox, the package manager, systemd. `FirstContact` does not save it: first contact
with a destination is a routine event, so the rule would fire on a large fraction of
new destinations by a large fraction of programs, all at medium severity, forever.
Simultaneously the suppressor's trusted-publisher gate becomes dead code, so every
*other* low/medium finding loses its main silencer too.

**macOS is fine here.** Code signing is near-universal on modern macOS, Developer ID
team identifiers are a direct analogue of the Authenticode CN, and `codesign` /
`SecStaticCode` give the same yes/no/who answer. The `trustedSigners` list needs new
values, not a new design.

**Linux has no analogue.** Executables are not signed in any way a desktop can
verify. The nearest substitutes are all worse:

- **Package-manager provenance** — `dpkg -S` / `rpm -qf` tells you whether a binary
  is owned by an installed package, and the package came from a repository whose
  metadata was GPG-signed. This is genuinely the right idea, and it is a real
  research task: it is distro-specific, it is slow (a subprocess per unique binary,
  where the Windows path already costs ~200 ms per binary via PowerShell), it says
  nothing about anything installed outside the package manager, and Flatpak, Snap,
  AppImage, `pip`, `npm`, `cargo install` and `curl | sh` all fall outside it — which
  on a developer's machine is most of the interesting software.
- **IMA/EVM** — the kernel's integrity measurement architecture exists but is not
  enabled or provisioned on any mainstream consumer desktop.
- **Give up on trust and lean harder on novelty scoring** — plausible, but it means
  the Linux product's noise control is a different design that has never been tested,
  in a product whose false-positive rate on its *tested* design is still unmeasured.

**Cost:** 2–3 engineer-weeks to build a package-provenance trust source, plus real
risk that it does not work well enough. This should be treated as the Linux port's
single biggest technical unknown, ahead of the sensor.

### 1.4 Structural leak #2: persistence is Windows-shaped through six layers

"Something arranged to run automatically" is modelled as Windows registry mechanics
at every level:

| Layer | File | What is Windows-specific |
|---|---|---|
| Event vocabulary | `event/event.go:67` | `PersistKind` documented as `run-key\|service\|scheduled-task\|startup-folder\|wmi` |
| Taxonomy | `autostart/autostart.go:21-30` | `Kind` enum: RunKey, RunOnce, Winlogon, IFEO, AppInit |
| Wording | `autostart/autostart.go:33-51` | `Describe()`: "run as part of the Windows sign-in process" |
| Parsing | `autostart/autostart.go:127-148` | `TargetPath` finds the executable by searching for `.exe` |
| Scanner | `autostart/scan_windows.go` | 172 lines of registry walking |
| Detectors | `detect/persistence.go` | `suspiciousDirs` = `\appdata\local\temp\`, `\programdata\`…; `describeLocation` names Windows folders; `detectUnsignedAutostart` special-cases `c:\windows\` |
| Rule pack | `rules/persistence.yaml` | 4 rules; 12 Windows-specific phrases |
| Response | `respond/exec_windows.go` | registry delete + restore |
| Undo safety | `respond/respond.go:252-271` | `autostartKeyPrefixes` — an allowlist of eight registry paths, load-bearing for security |

Note the last row. `ValidateUndo` refuses to reverse an autostart removal unless the
recorded location starts with one of eight hardcoded `hkcu\...` / `hklm\...` strings.
That check exists because undo records are read back from a database an attacker may
be able to write, and without it the reversal is an arbitrary registry write as
SYSTEM. Any port must re-derive an equivalent allowlist for its own persistence
locations, and get it right, or reintroduce a privilege-escalation primitive. This is
the least glamorous and highest-risk part of the whole port.

Linux has *more* autostart mechanisms than Windows, not fewer — systemd system and
user units, systemd timers, `~/.config/autostart`, `/etc/xdg/autostart`, cron in five
locations, `at`, shell rc files, `LD_PRELOAD` and `/etc/ld.so.preload`, udev rules,
PAM modules, kernel modules, `/etc/rc.local`, Polkit rules, D-Bus service files,
NetworkManager dispatcher scripts, GRUB, initramfs
([MITRE T1543.002](https://attack.mitre.org/techniques/T1543/002/),
[T1053.003](https://attack.mitre.org/techniques/T1053/003/),
[T1547.013](https://attack.mitre.org/techniques/T1547/013/),
[T1574.006](https://attack.mitre.org/techniques/T1574/006/);
[Elastic Security Labs, *The Grand Finale on Linux Persistence*](https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence)).

A defensible v1 scope is the **user-level, no-root subset** — `~/.config/autostart`,
`~/.config/systemd/user`, shell rc files, the user crontab. That is where consumer
malware would live for the same reason it lives in HKCU on Windows: it needs no
administrator rights. It is also cheap to watch.

macOS is narrower and cleaner: LaunchAgents and LaunchDaemons in the five standard
directories, login items / `SMAppService`, `BackgroundTaskManagement`, cron,
configuration profiles.

### 1.5 The other five leaks (mechanical, but real)

**Path semantics.** `filewatch/classify.go` (197 lines) is Windows-shaped
essentially in full: `Classify` normalises forward slashes *to* backslashes
(lines 93-94), `userDirs` is a list of `\documents\`-style fragments, and
`credentialPaths` keys on Windows AppData locations with `.exe` owner names
(`chrome.exe`, `firefox.exe`). `graph/narrate.go:177` does the same slash inversion.
This file needs a rewrite per platform, not a parameterisation — the *paths* differ,
but so does the shape (macOS `~/Library/Application Support/Google/Chrome/...`,
Linux `~/.config/google-chrome/...`, plus the system Keychain on macOS which is not a
file-read event at all).

**`c:\windows\` prefix checks.** `detect/files.go:124` and
`detect/persistence.go:155` both hardcode it as a "this is the OS, not malware"
exclusion.

**The shell/lineage heuristic.** `graph/context.go:46-50` — `shells` is
`{explorer.exe, cmd.exe, powershell.exe, pwsh.exe, wt.exe, conhost.exe, userinit.exe,
taskmgr.exe}`, and `UserLaunched` is derived from membership. On Linux and macOS this
map matches nothing, so `UserLaunched` is always false and every narrative loses the
"which usually means you opened it" clause — which is one of the genuinely good
sentences the product produces. Linux needs `gnome-shell`, `plasmashell`, `bash`,
`zsh`, `nautilus`, `dolphin`, and the terminal emulators; macOS needs `Finder`,
`Dock`, `launchd` disambiguation, `Terminal`, `iTerm2`.

**Service naming.** `platform.ProcInfo.Services` and `collector.labelWithServices`
exist to turn "svchost.exe" into "Windows Update (svchost.exe)". There is no
equivalent problem on Linux or macOS — systemd units and launchd jobs run as
distinctly-named binaries. The field can stay and go unused; the display path needs a
conditional so it does not render an empty prefix.

**PID semantics — this one gets *better*, not worse.** `known-limitations.md`
records that attribution keys on PID and that "Sysmon's ProcessGuid would fix this
properly." Both target platforms hand us that for free: eBPF can key on
`(pid, task start time)`, and macOS EndpointSecurity supplies `audit_token_t`, which
is unique by construction. `NormalizedEvent.PID uint32` is fine as a field on both
(`pid_t` is a signed 32-bit int on Linux and Darwin); the improvement would come from
adding an optional stable-identity field, which is additive and does not break the
Windows path.

**Response actions and wording.** `respond/respond.go` is mostly portable in
structure — `Suggest` orders actions by destructiveness, which is a product decision
that translates — but the `Detail` strings say "Adds a Windows Firewall rule", and
`underDir`/`normWin` (lines 279-311) deliberately implement Windows path semantics
with a comment explaining that using `path/filepath` would silently accept traversal
when the tests run on Linux. A port needs a second, POSIX-correct implementation of
the same safety check, selected by platform — and must not simply switch to
`filepath`, or the Windows check breaks.

### 1.6 Seam verdict

Replacing the sensor gets a Linux or macOS build that *records* things. Getting a
build that *is the product* additionally requires: a new trust source (Linux only,
and hard), a new persistence model through six layers, three rewritten classification
tables, a rewritten response executor with its own undo-safety allowlist, and a
rewritten set of alert narratives.

Useful ratio: the Windows sensor is 479 lines. The Windows-specific *everything else*
is about 2,100 lines plus 312 lines of rule YAML. **The sensor is roughly a fifth of
the port.**

---

## Part 2 — Linux

### 2.1 Does eBPF violate "no kernel driver, ever"? — a judgement call, argued

`CLAUDE.md` says: *"Telemetry: userland ETW consumers. **No kernel driver, ever, in
this product line.**"* The design doc's rationale is that active blocking "requires
signed minifilter/WFP drivers" and WHQL signing; `known-limitations.md` frames the
consequence as *"No kernel driver, so nothing is blocked before it happens.
NiteWatch observes and advises; it never sits in the path of an operation."*

So the rule bundles three separate commitments:

1. **Do not ship code that can crash the user's machine.**
2. **Do not take on a driver-signing regime** (WHQL, kext approval).
3. **Stay out of the operation path** — observe, never block.

Against those three:

1. eBPF programs run *in kernel context* but are checked by the in-kernel verifier
   before load — bounded loops, no arbitrary memory writes, no unchecked pointer
   dereference. This is the explicit design difference from a kernel module. Note
   the honest caveat: verifier CVEs exist, and eBPF-based sensors have caused
   production incidents; "cannot crash the kernel" is a strong claim, not an absolute
   one.
2. There is no signing regime. You load an ELF as root. No vendor gate, no WHQL
   analogue, nothing that can be revoked.
3. Observation-only program types — `tracepoint`, `kprobe`, `perf_event`, ring
   buffer output — do not sit in the path. But eBPF *also* offers BPF-LSM (which can
   deny an operation), `bpf_probe_write_user`, and XDP drop. **Those do violate
   commitment 3.**

Industry precedent is directly on point: CrowdStrike's Falcon sensor for Linux calls
its eBPF backend **"user mode"** and contrasts it with **"kernel mode"** — the actual
kernel module
([CrowdStrike, *Installing Falcon Sensor for Linux*](https://www.crowdstrike.com/tech-hub/endpoint-security/installing-falcon-sensor-for-linux/)).
The whole post-2024 industry argument for eBPF sensors is that they are *not*
kernel modules
([The New Stack](https://thenewstack.io/crowdstrike-a-wake-up-call-for-ebpf-based-endpoint-security/)).

**Verdict: eBPF satisfies the rule as written, conditionally.** It satisfies all
three commitments *if and only if* the port is scoped to observation-only program
types, with BPF-LSM, `bpf_probe_write_user` and XDP-drop explicitly forbidden. Under
a stricter reading — "no code of ours executes in kernel context, full stop" — eBPF
is excluded, and Section 2.5 costs the non-eBPF alternative.

**This needs Kevin's call, and CLAUDE.md should be amended either way** to state what
the rule protects rather than leaving "kernel driver" as a proxy that a new
technology can slip past on a technicality. Suggested wording if eBPF is accepted:
*"No kernel driver, and no code that can deny or delay an operation. Verified,
observation-only in-kernel telemetry (eBPF tracepoints/kprobes) is permitted;
BPF-LSM, `bpf_probe_write_user` and XDP drop are not."*

### 2.2 The eBPF option, in detail

**Library: `cilium/ebpf`.** It is pure Go and talks to the kernel via raw `bpf(2)`
syscalls — "does not depend on C, libbpf, or any other Go libraries other than the
standard library" ([github.com/cilium/ebpf](https://github.com/cilium/ebpf)). Latest
release v0.22.0 (2026-06-29). Actively maintained by Cloudflare and Cilium; it is the
loader inside Cilium, Tetragon and Grafana Beyla. Still pre-1.0 after seven years with
breaking changes at most minors — budget for upgrade churn.

**CGO: preserved, with a build-pipeline cost.** The Go side is CGO-free. The BPF
programs themselves are C and must be compiled by clang/LLVM 11+ at *build* time;
`bpf2go` emits the `.o` and a Go file that `go:embed`s it, so the shipped binary
contains no separate object files and builds with `CGO_ENABLED=0`
([bpf2go docs](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go),
[ebpf-go getting started](https://ebpf-go.dev/guides/getting-started/)). The
recommended practice is to compile in a pinned container and **commit the generated
`.o` and `.go`**, so CI and contributors do not need clang
([portable eBPF guide](https://ebpf-go.dev/guides/portable-ebpf/)). There is no
pure-Go C→BPF compiler; the library's own assembler only covers trivial programs.

*Unconfirmed:* I could not find a first-party sentence stating `CGO_ENABLED=0` works.
It follows from the "no C, stdlib only" claim and is confirmed by multiple
third-party build recipes, but a one-line build test would settle it in minutes.

**`libbpfgo` is the wrong choice for us** — it "uses CGO to interop with libbpf and
will expect to be linked with libbpf at run or link time"
([aquasecurity/libbpfgo](https://github.com/aquasecurity/libbpfgo)). That breaks the
CGO-free constraint outright.

**Portability across kernels (CO-RE / BTF).** `cilium/ebpf` implements BTF
relocations natively in Go, reading `/sys/kernel/btf/vmlinux`. Kernels without BTF
need external BTF blobs supplied via `ProgramOptions.KernelTypes`, typically from
BTFHub. Per [BTFHub's supported-distros list](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md):
Ubuntu 20.10+, Debian 11+, Fedora 32+, RHEL/CentOS 8.2+ have native BTF;
**Ubuntu 20.04 and RHEL/CentOS 7 do not** and would need shipped BTF blobs — which
means a per-kernel artifact matrix, partly defeating "one binary everywhere." The
external-BTF path is also reported as not turnkey
([cilium/ebpf discussion #1222](https://github.com/cilium/ebpf/discussions/1222)).

*Recommendation if this proceeds: set the floor at kernel 5.8 with native BTF, and
say so, rather than shipping a BTF matrix.* That covers Ubuntu 20.10+, Debian 11+,
Fedora 32+, and every rolling distro — which is nearly all of a consumer install
base in 2026 — and drops the hardest part of the portability story.

**Privileges.** Kernel 5.8+ splits the old CAP_SYS_ADMIN blanket:

| Program class | Capabilities |
|---|---|
| kprobe / tracepoint / perf_event / tracing | **CAP_BPF + CAP_PERFMON** |
| tc, XDP, most networking | CAP_BPF + CAP_NET_ADMIN |

([mdaverde, *Introduction to CAP_BPF*](https://www.mdaverde.com/posts/cap-bpf/);
[LWN, *A crop of new capabilities*](https://lwn.net/Articles/822362/)).

**An unprivileged mode is not possible.** Unprivileged BPF only ever permitted
`BPF_PROG_TYPE_SOCKET_FILTER`, never tracing, and it is disabled by default on
Ubuntu, SUSE and Red Hat anyway
([Ubuntu Discourse](https://discourse.ubuntu.com/t/unprivileged-ebpf-disabled-by-default-for-ubuntu-20-04-lts-18-04-lts-16-04-esm/27047),
[SUSE KB](https://support.scc.suse.com/s/kb/Security-Hardening-Use-of-eBPF-by-unprivileged-users-has-been-disabled-by-default)).
This is not a regression from Windows — ETW also requires Administrator — but it does
mean a root systemd daemon plus an install story, which for a consumer product is real
UX work.

**Kernel lockdown / Secure Boot.** `lockdown=integrity` does not block loading
legitimate BPF as root. `lockdown=confidentiality` blocks BPF kprobe reads of kernel
memory and *will* break the sensor. Fedora deliberately defaults to `integrity` so
eBPF works with Secure Boot on
([Djalal Harouni](https://djalal.opendz.org/post/ebpf-kernel-image-lockdown-and-ebpf-flexibility/)).
**Unconfirmed:** Ubuntu's and Debian's 2026 lockdown mode under Secure Boot. Test on a
Secure Boot machine before committing.

### 2.3 Can eBPF supply the four things the causal graph needs?

| Need | Verdict | Mechanism and caveat |
|---|---|---|
| **Process lineage** | **Yes — parity or better** | `tracepoint/sched/sched_process_exec` and `sched_process_fork`. Use these, *not* `syscalls/sys_enter_execve`, which is documented as unreliable. Caveat: the 512-byte eBPF stack vs `PATH_MAX` 4096 means paths and argv need per-CPU scratch maps or chunked ring-buffer streaming. |
| **Process-attributed connections** | **Yes, for outbound** | `tracepoint/syscalls/sys_enter_connect` gives PID + sockaddr directly. `sock/inet_sock_set_state` gives the TCP lifecycle but the PID is only valid on the `CLOSE→SYN_SENT` transition — stash the initiator PID in a map keyed by `struct sock *`. Not reliable for accepted/inbound or kernel-initiated sockets. Since NiteWatch is an outbound-focused product, this is fine. |
| **File events** | **Yes** | kprobe on `vfs_write`, or fanotify (Section 2.5). Note `mmap(PROT_EXEC)` is invisible to fanotify but catchable via eBPF. Volume on a desktop is the real constraint, same as Windows' Kernel-File provider — the existing `interestingPath` filtering approach transfers. |
| **DNS** | **No — this is the blocker** | See below. |

**DNS is where the Linux port loses the product's headline feature.** The README's
first bullet promises a connection log that names *"which domain"*, and the design
doc calls the DNS join *"the thing netstat can never tell you."* On Linux:

- **uprobe on `getaddrinfo`** works for dynamically-linked glibc C programs. It does
  **not** work for Go programs, which prefer a pure-Go resolver that reads
  `/etc/resolv.conf` and sends DNS directly, bypassing libc entirely
  ([pkg.go.dev/net](https://pkg.go.dev/net)). Same blindness for statically-linked
  musl, Rust with hickory-dns, and browsers with their own stub resolvers. The irony
  is direct: a `CGO_ENABLED=0` agent cannot see programs built the way it is built.
- **uprobes are also actively defeatable** — a program can detect the `0xcc`
  breakpoint in its own `.text`, or prevent probe installation by making its
  executable segment writable
  ([Quarkslab, *Defeating eBPF Uprobe Monitoring*](https://blog.quarkslab.com/defeating-ebpf-uprobe-monitoring.html)).
- **tc/socket-filter parsing of UDP 53** is language-agnostic and robust, but
  **loses PID attribution** unless you correlate the skb back to a socket, and misses
  DNS-over-TCP unless handled separately.
- **DNS-over-HTTPS defeats all of it.** Firefox and Chrome enable DoH by default in
  many regions; the traffic is indistinguishable from ordinary HTTPS
  ([Wikipedia, DoH](https://en.wikipedia.org/wiki/DNS_over_HTTPS)). ECH is eroding
  SNI as the fallback.

Windows gets this nearly free from `Microsoft-Windows-DNS-Client`, which sits below
the application and above the wire. Linux has no equivalent single vantage point.

**Consequence, stated honestly:** the Linux product's connection ledger would show
IP + AS owner + country reliably, and *domain* only some of the time (reverse DNS,
which the code already does as a fallback via `internal/resolve`, plus best-effort
passive capture). That is a materially weaker product than the Windows one, and the
marketing must say so — the marketing-honesty rule applies.

### 2.4 What Linux would give us that Windows does not

Worth recording, because it is not nothing:

- **Command lines.** `known-limitations.md` records that raw ETW `Kernel-Process`
  supplies neither command lines nor file hashes, ruling out living-off-the-land
  argument detection. eBPF `sched_process_exec` gives argv (with the truncation
  caveat above). That is an entire class of detection Windows currently cannot do.
- **Stable process identity.** `(pid, start_time)` fixes the PID-recycling
  misattribution documented as a structural gap.
- **No PowerShell shell-outs.** The Windows signer check costs ~200 ms per unique
  binary via `Get-AuthenticodeSignature`. There is no equivalent tax on Linux —
  though there is also nothing to check (Section 1.3).

### 2.5 The non-eBPF Linux path (if eBPF is ruled out)

Costed because commitment 1 in Section 2.1 might be read strictly.

| Source | CGO | Gives | Problem |
|---|---|---|---|
| Audit netlink via `elastic/go-libaudit` | **CGO-free** — raw `AF_NETLINK` socket | execve, connect, file watches | **Conflicts with auditd.** The kernel unicasts audit events to one registered PID; go-libaudit's README says "the system's auditd process should be stopped first." *A consumer security product that disables the system's audit daemon is a hostile neighbour.* The read-only multicast group allows coexistence but cannot install rules. |
| fanotify | CGO-free via `golang.org/x/sys/unix` | file events **with the responsible PID** (`FAN_REPORT_PIDFD`, 5.15) | Needs **CAP_SYS_ADMIN**. Whole-mount `FAN_MODIFY` is viable in principle — it is how ClamAV's on-access scanner works — but is very high volume on a desktop. Blind to mmap writes. Permission-class events risk deadlock if the handler blocks. |
| netlink `sock_diag` | CGO-free | connection table snapshots | **No PID field** — `inet_diag_msg` carries UID and socket inode only ([sock_diag(7)](https://man7.org/linux/man-pages/man7/sock_diag.7.html)). Getting the PID means walking `/proc/*/fd`, which is O(processes × fds) and racy. |
| `connector`/`cn_proc` | CGO-free | fork/exec/exit notifications | Needs root or CAP_NET_ADMIN, and carries **only numeric PIDs** — you must race to `/proc/<pid>/exe`, and lose short-lived processes. Tells you *that* something ran, not *what*. |
| `/proc` polling | CGO-free | process table | Misses short-lived processes by construction; PID-reuse races. Fine as a reconciliation layer, never as the primary. |
| inotify | CGO-free | file events | **No PID attribution at all** — [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html) is explicit. Not viable for security telemetry. |

**A non-eBPF Linux sensor is buildable** — audit-netlink for exec/connect plus
fanotify for files plus `/proc` reconciliation — at roughly comparable effort, but
the auditd conflict is a genuine product problem and DNS is no better. Not
recommended; if eBPF is ruled out, the recommendation becomes "no Linux port."

### 2.6 Market reality

StatCounter, worldwide desktop, June 2026: Windows 56.6%, "Unknown" 21.5%, OS X
11.9%, macOS 4.5%, **Linux 4.4%**, ChromeOS 1.2%
([gs.statcounter.com](https://gs.statcounter.com/os-market-share/desktop/worldwide)).
The 21.5% "Unknown" bucket is a large caveat — these are web-traffic estimates, not
installed-base counts, and Linux's apparent growth is partly a classification
artifact. Treat "~4%" as an upper-bound-ish estimate.

More decisive than the size is the **shape**: there is essentially no consumer,
non-technical Linux desktop market. Linux-preinstall OEMs (System76, Tuxedo) sell to
an already-technical audience. The growth drivers everyone cites (Windows 10 EOL,
privacy, cost) select for *more* self-sufficient users. And the fastest-growing
consumer-facing slice — SteamOS handhelds — runs an immutable root filesystem
actively hostile to installing a third-party root daemon, on devices whose users are
not an endpoint-security market.

**And the space is already served for free.** OpenSnitch (eBPF backend, per-process
outbound prompts, GPL) and Portmaster both do the connection-monitoring half; Little
Snitch shipped a Linux version in 2026. NiteWatch's differentiator — the causal story
and the plain-English narrative — is real and none of those have it. But the price
point a technical Linux user will pay for a nicer explanation of data they can already
get free is a question worth asking before spending five months.

---

## Part 3 — macOS

### 3.1 The EndpointSecurity entitlement is a business risk, not just an engineering one

`com.apple.developer.endpoint-security.client` is what Apple calls a **restricted
entitlement**: it must be granted per developer team, it must be authorised by a
provisioning profile embedded in the app, and there is an application form.

What could be established, with sources:

- **It is approval-gated and team-scoped.** Apple DTS: *"The EndpointSecurity
  entitlement (`com.apple.developer.endpoint-security.client`) is a **special**
  entitlement. You must be granted access to it by Apple. The documentation includes a
  link to the application form."*
  ([Apple Developer Forums 655467](https://developer.apple.com/forums/thread/655467))
- **Development without approval is possible; shipping is not.** Same thread, on
  whether the entitlement is mandatory: *"For deployment, yes. For initial bringup you
  can test ES by disabling SIP (on a 'victim' machine, of course)."* So the sensor can
  be *built and validated* before applying — which is a useful de-risking order, and
  the only one available.
- **The approval odds are genuinely unknowable in advance.** A solo developer asked
  precisely our question — realistic chances for a behavioural-monitoring tool,
  common rejection reasons. Apple DTS answered: *"I don't think you'll get a
  definitive answer to this here on DevForums. The folks who approve access to this
  capability don't lurk here. My general advice would be to 'Suck it and see.'"*
  ([Apple Developer Forums 820718](https://developer.apple.com/forums/thread/820718))
  **Nobody outside Apple can quote a rejection rate.** Any number in this document
  would be invented.
- **The wait is long and the rejection is opaque.** Reported turnarounds: three
  months for development access and a further three months to have distribution
  *denied* ([Forums 767311](https://developer.apple.com/forums/thread/767311)); four
  months with no reply; twelve months with no reply
  ([Forums 133494](https://developer.apple.com/forums/thread/133494),
  [736042](https://developer.apple.com/forums/thread/736042)). Rejections are
  boilerplate with no reason given: *"After careful consideration, we regret that
  we're unable to approve your request at this time."* Forum posts over-represent
  bad outcomes, so read these as the tail, not the median — but the tail is long
  enough to plan around.
- **Development approval does not imply distribution approval.** There is a
  documented case of a company **granted development access and denied distribution
  access** for the same entitlement, with Apple DTS confirming there is no workaround:
  *"Enterprise distribution isn't a thing on macOS. The nearest equivalent is direct
  distribution using Developer ID, but you've already been denied that."*
  ([Apple Developer Forums 759149](https://developer.apple.com/forums/thread/759149))
- **Mechanics.** It is now a Capability Request in the developer portal
  (Certificates, Identifiers & Profiles → Identifiers → the App ID → *Capability
  Requests*), and **only the Account Holder can submit one**
  ([Apple account help](https://developer.apple.com/help/account/capabilities/capability-requests/)).
- **Individual vs Organization enrollment: unresolved.** No Apple statement was
  found requiring an Organization account, and DTS did not raise account type when
  answering the solo developer above. Threat Tape LLC can enroll as an Organization
  regardless, so this is not a blocker — but it is not confirmed either way.

**That last point is the risk that should decide this.** It is possible to spend six
months building a macOS sensor, get development approval, finish the product, and then
be unable to ship it — with no appeal, no enterprise fallback, and no alternative
distribution channel. That is a project-killing outcome that arrives *after* the money
is spent.

Mitigations, in order of cost:
1. **Apply first, build second.** Threat Tape LLC is a legal entity, so an
   Organization Apple Developer account ($99/yr, requires a free D-U-N-S number
   — [Apple](https://developer.apple.com/help/account/membership/D-U-N-S)) is
   available. Submit the request with the real product description and a working
   Windows product to point at, *before* committing engineering time. Cost: ~1 week
   of admin plus unknown waiting. This is cheap and should be done regardless of
   whether the port proceeds — it converts an unbounded unknown into a fact.
2. Explicitly ask for **distribution**, not just development, and treat a
   development-only grant as a red flag rather than a green light.
3. Have the non-entitled fallback (Section 3.3) costed before applying, so a denial
   is a scope decision rather than a dead end.

### 3.2 NetworkExtension is a different and much better story

`com.apple.developer.networking.networkextension` with `content-filter-provider` is
**not** approval-gated. Apple DTS, asked directly about the approval process: *"There
is no approval process for this. Most NE entitlements, including the one for content
filters, are available to all (paid) developers"* — historically there was one, but
*"this has not been the case for almost 10 years."*
([Apple Developer Forums 816877](https://developer.apple.com/forums/thread/816877))

`NEFilterDataProvider` sees TCP and UDP flows and other IP traffic, and
`NEFilterFlow.sourceAppAuditToken` gives the originating process's audit token, from
which the PID and UID are derivable
([Apple docs](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)).
The deployment restrictions in TN3134 that block general content filters outside MDM
are **iOS-specific**; the existence proof for macOS is Objective-See's LuLu — a
Developer ID-signed, notarized, freely downloadable network extension that ordinary
users install with a System Settings approval and no MDM
([objective-see.org/products/lulu.html](https://objective-see.org/products/lulu.html)).

**Consequence: the connection ledger — P1, the flight recorder, the thing the product
is named for — is achievable on macOS without any restricted entitlement.** Only the
process/file/exec telemetry (P2's detections) needs EndpointSecurity. That is a much
better risk shape than "all or nothing," and it suggests a natural phasing if macOS
ever proceeds.

Note: ES and NE cannot live in the same system extension, though both can ship in one
container app ([Forums 655467](https://developer.apple.com/forums/thread/655467)).

**Correction to a common assumption: EndpointSecurity does *not* require a system
extension.** Per Apple DTS, *"the majority of ES products are daemon-based rather
than system extensions."* A plain `launchd` daemon works, provided it is packaged in
an app-like bundle, signed with Developer ID Application, carries an embedded
provisioning profile containing the ES entitlement, and is notarized
([Forums 791996](https://developer.apple.com/forums/thread/791996);
[Signing a daemon with a restricted entitlement](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement)).
That is a materially simpler shape than a sysex. **But** the ES client also requires
**Full Disk Access**, which the user can only grant to something that appears in the
FDA list — hence the app bundle, and hence `SMAppService` with the daemon under
`Contents/Helpers/`. Splitting ES subscription and FDA-gated work across separate
processes does not work; DTS states requiring FDA was deliberate
([Forums 804548](https://developer.apple.com/forums/thread/804548)). **Architect for
the app-bundle-wrapped-daemon shape from day one** — retrofitting it is painful.

So a full macOS NiteWatch is: container app + ES daemon (or sysex) + NE content-filter
sysex. Three components, not one binary — but the NE filter alone is a complete P1.

### 3.3 What is achievable with no restricted entitlement at all

- `proc_listpids` / `proc_listallpids` / `proc_pidinfo` — process enumeration with
  paths. Works; **as root** to see other users' processes.
- `proc_pidfdinfo` with `PROC_PIDFDSOCKETINFO` — per-process socket enumeration,
  which is how `lsof` works. Polling, so short-lived connections are missed.
- `nettop`, `lsof`, `netstat` — same data, via subprocess.
- Unified logging (`log stream`) — **not usable.** Redaction happens at *write* time;
  once a field is written as `<private>` the data is gone and cannot be recovered at
  read time. DNS specifically: mDNSResponder stopped logging query names publicly,
  and `log config --mode "private_data:on"` now itself requires SIP disabled.
- OpenBSM / `auditd` — **dead end.** Deprecated since macOS 11, disabled by default
  since Sonoma, and Apple's own man page directs anything needing a security event
  stream to EndpointSecurity. Do not build on it.
- **Unconfirmed:** whether `proc_pidfdinfo` remains fully functional as root without
  entitlements on macOS 15/26. No report of restriction found, and `lsof` still ships
  and works, but no authoritative 2026 statement either. Worth a 30-minute test on a
  current Mac before relying on it.

**The finding that changes this section: `eslogger`.** `/usr/bin/eslogger` is an
Apple-signed, Apple-*entitled* EndpointSecurity client shipped with macOS since
Ventura 13.0. It streams ES events as JSON to stdout. It needs **root plus Full Disk
Access** and **no entitlement of ours**. `sudo eslogger --list-events` enumerates
roughly 82 event types including `exec`, `fork`, `open`, `create`, `unlink`,
`uipc_connect`, `kextload` and `btm_launch_item_add` — which is to say: real process
lineage, real file events, and real persistence events, on a stock SIP-enabled Mac,
today, with no approval from anyone
([Cybereason](https://www.cybereason.com/blog/blue-teaming-on-macos-with-eslogger),
[eslogger(1)](https://keith.github.io/xcode-man-pages/eslogger.1.html)). A Go project
already does exactly this ([tstromberg/esl](https://github.com/tstromberg/esl)).

Apple's man page disclaims it in terms: *"eslogger is not intended to be used by
applications. It is not meant to provide the same functionality, performance and
schema stability as natively interfacing with the Endpoint Security API does."* Take
that seriously — it is NOTIFY-only (no blocking, which suits us), it means managing a
subprocess and parsing JSON, the event volume is brutal and must be filtered hard,
there is no schema-stability promise, and Apple could restrict it at any release.

**Revised verdict on the non-entitled path.** Polling libproc alone would be a nicer
`lsof` and not a product. But **`NEFilterDataProvider` + `eslogger` + libproc
together get surprisingly close to the whole thing** — attributed network flows, exec
events with lineage, file events, persistence events. That is a genuine prototype
path, and more importantly it is a *sequencing* insight: the macOS sensor can be
built and validated, and the causal graph proven on real Mac telemetry, **before
applying for the entitlement and while waiting for the answer.** The entitlement then
becomes an upgrade from a working prototype to a shippable product, rather than a
gate that must clear before work can start.

**Unconfirmed:** whether `eslogger` still behaves this way on macOS 26 — every
detailed writeup found is Ventura/Sonoma-era. Resolved by running
`sudo eslogger --list-events` on a current Mac.

### 3.4 CGO on macOS: harder than Windows, but not flatly impossible

Stated carefully because the constraint is explicit in CLAUDE.md, and because the
obvious answer turns out to be slightly wrong.

**Neither API is a syscall interface.** EndpointSecurity is a C API (`es_new_client`,
`es_subscribe`, block-based handlers) in a linked system framework. NetworkExtension
is Objective-C with *subclassing* — the system instantiates your `NEFilterDataProvider`
subclass by principal class name — which is a class-registration problem, not an FFI
problem. So `syscall` is out for both.

**NetworkExtension: a native shim is unavoidable.** No usable Go bindings exist and
none plausibly could, given the subclassing requirement. This part is Swift or
Objective-C, full stop.

**EndpointSecurity: a CGO-free route now exists, unproven.**
`github.com/tmc/apple/endpointsecurity` (pushed 2026-07-15) is cgo-free — it
`dlopen`s the framework via `purego`, registers each symbol with per-symbol OS
availability metadata, and handles the `es_new_client` handler block through
`objc.NewBlock`. That last part matters: block callbacks were the reason to assume
purego could not work here, and purego does support them.

I am *not* recommending it. The risks are specific and serious:

- `es_message_t` is a large, deeply nested, **versioned** C struct that Apple revises
  across macOS releases. purego bindings must hand-mirror that layout. **A layout
  mismatch is silent memory corruption, not a compile error** — in an elevated
  security agent.
- ES messages are reference-counted (`es_retain_message` / `es_release_message`) and
  purego cannot manage lifetimes across the boundary; that is manual and easy to get
  wrong.
- The package is autogenerated from Apple's documentation, has zero importers, and
  there is no evidence anyone has run it against a real entitled client.

The other Go options are worse: `gatkinso/gomac/endpointsecurity` documents its own
CGo bridge as *"added in a later phase — until then, all client functions compile and
return stub values"* and its GitHub repo now 404s; `xorrior/goesf` is cgo + Objective-C,
29 stars, and last touched in 2019.

**Recommended architecture regardless: a native shim, not purego.** A small
Objective-C or Swift component owns the ES and NE clients and forwards normalized
events over XPC or a local socket to the existing Go agent. This is the boring choice
and the right one: it is the only option for NetworkExtension anyway, so purego would
buy a CGO-free ES path while still requiring a native NE component — most of the cost
with none of the safety. It also keeps the Go core CGO-free and preserves the
`EventSource` seam beautifully: the macOS `EventSource` becomes a socket reader,
barely more than `replay.go`.

One further design note from the research, worth recording: **subscribe NOTIFY-only.**
ES AUTH events carry deadlines, and missing one kills the client. A Go GC pause inside
an AUTH deadline is a hazard with no clean mitigation. NiteWatch never blocks
operations by design, so NOTIFY-only costs us nothing and removes the whole class.

The native-shim architecture means:

- shipping a second language and an Xcode build in the pipeline,
- a multi-process design with its own IPC to secure (this is an *elevated* process
  boundary; every lesson in `known-limitations.md` about untrusted input to an
  elevated process applies again, from scratch),
- a macOS build that can only be produced on macOS, ending the "cross-compile from
  the WSL2 box" workflow for that target.

**Recommended constraint amendment if macOS ever proceeds:** scope the rule to
*"CGO-free on Windows and Linux; the macOS sensor shim is native code, and the Go
agent remains CGO-free on every platform."* That preserves what the constraint was
actually protecting — a single static Go binary with no runtime C dependency — while
admitting the one place it cannot hold. Note the amendment is about the *shim*, not
the agent: even on macOS the Go binary stays CGO-free under this design, which is a
better outcome than the constraint's authors probably expected.

### 3.5 Signing, notarization, distribution

macOS is strictly harder than Windows here, and NiteWatch is currently unsigned on
Windows.

Required to ship: Apple Developer Program membership ($99/yr); a Developer ID
Application certificate; hardened runtime enabled; notarization via `notarytool`
(`altool` was retired in 2023); the ticket stapled to the artifact; a `.pkg`
installer; `com.apple.developer.system-extension.install` on the container app; and —
for any restricted entitlement — an **embedded provisioning profile** at
`Contents/embedded.provisionprofile` whose `com.apple.application-identifier` matches
the signature, or the app crashes on launch with `EXC_CRASH (Code Signature Invalid)`
([Forums 712570](https://developer.apple.com/forums/thread/712570)). Verify with
`syspolicy_check distribution` (macOS 14+) before shipping.

**MDM is not required.** Users on unmanaged Macs approve the system extension in
System Settings → General → Login Items & Extensions, approve the network filter
separately, and grant Full Disk Access manually. That is three consent steps before
the software does anything, which is a real conversion-rate problem for a consumer
product and should be designed for, not discovered.

Two ongoing costs worth naming: notarization requirements change with each major
macOS release, so extensions can need re-signing and re-notarizing per OS version;
and use **Apple Development** signing for day-to-day work and Developer ID only for
release — mixing them up is the documented cause of macOS 26's `sysextd` refusing
extensions with *"no policy, cannot allow apps outside /Applications"*
([Forums 820254](https://developer.apple.com/forums/thread/820254)).

Silver lining: notarization solves the SmartScreen-equivalent problem *by
construction*. The Windows product's "unsigned binary that looks like malware to
heuristics" issue has no macOS analogue, because you cannot ship at all without
being signed.

---

## Part 4 — Do the four rule packs survive translation?

The product's value is the causal story and the plain-English alert, not the
detection primitive. So the right test is not "can the detector fire" but "does the
sentence still make sense."

### c2.yaml (141 lines, 6 rules) — **survives, with one casualty**

| Rule | Linux | macOS |
|---|---|---|
| `c2-feed-flagged-connection` | Fine | Fine |
| `c2-raw-ip-no-dns` | **Broken.** Its premise is "connected without a name lookup first," which requires reliable DNS visibility we do not have. Absent DNS the detector fires on everything or nothing. | Fine (NEFilterDataProvider sees flows; DNS via ES or NE) |
| `c2-unsigned-first-contact` | **Broken** (Section 1.3) — no signatures exist | Fine |
| `c2-foreign-first-contact` | Fine — pure recon data | Fine |
| `c2-exfil-after-secret-read` | Fine, given file events | Needs ES (or `eslogger` in prototype) |
| `c2-beaconing` | Fine — timing only | Fine |

Narratives: 6 of 6 playbooks say "Run a full scan with Microsoft Defender (Start →
Windows Security → …)". Linux has no consumer AV to recommend, which is genuinely
awkward — the playbook step would become "disconnect and get help," which is weaker
advice. macOS can point at XProtect/Malware Removal Tool, or more honestly at
Objective-See's free tools.

### persistence.yaml (79 lines, 4 rules) — **does not survive; needs rewriting**

This pack is the most Windows-shaped thing in the product, and the most valuable.

- `persist-image-hijack` (IFEO/AppInit) — **no equivalent exists.** The nearest
  Linux analogue is `LD_PRELOAD` / `/etc/ld.so.preload`, and macOS's is
  `DYLD_INSERT_LIBRARIES`. Both are legitimately a "loads itself into other
  programs" story and the narrative *translates well* — *"Something arranged to load
  itself into every program you run"* is a great sentence — but it is a new rule with
  a new detector, not a port.
- `persist-autostart-replaced` — translates cleanly. "An existing startup entry now
  runs something else" is true of a systemd unit's `ExecStart` or a LaunchAgent's
  `ProgramArguments`. **This is the best-travelling rule in the pack.**
- `persist-from-temp-location` — translates in shape, but `suspiciousDirs` must be
  rebuilt (`/tmp`, `/dev/shm`, `~/Downloads`, `~/.cache` on Linux;
  `/tmp`, `~/Downloads`, `~/Library/Caches` on macOS). Note `/tmp` execution is far
  more normal on a developer's Linux box than `%TEMP%` execution is on a consumer
  Windows box — this rule's false-positive profile is worse on Linux.
- `persist-unsigned-autostart` — **dead on Linux** (no signatures). Works on macOS.

Every narrative says "start with Windows" and points at "Task Manager → Startup
apps". Linux has no single such UI to point at; macOS has System Settings → General →
Login Items, which is a good pointer.

**Verdict: the persistence pack is a rewrite on both platforms.** Two of four rules
survive on macOS; one and a half on Linux.

### ransomware.yaml (64 lines, 3 rules) — **survives best of the four**

The detection is behavioural — 40 document writes in 60 seconds across directories,
encryption-looking renames, ransom notes — and behaviour is behaviour. Only the
lookup tables change: `userDirs` becomes `~/Documents`, `~/Pictures`, XDG user dirs
on Linux; the same plus iCloud Drive on macOS.

One rule needs replacing: `ransomware-backup-destruction` keys on
`vssadmin.exe`/`wbadmin.exe`/`bcdedit.exe`/`wmic.exe`. Linux equivalents are weaker
and noisier (deleting `.snapshots`, `btrfs subvolume delete`, `timeshift --delete`,
`restic forget`). **macOS has a genuinely strong equivalent** — `tmutil delete` /
`tmutil disable` against Time Machine local snapshots, which is a real and
well-documented ransomware behaviour, and the narrative *"something is deleting your
ability to recover files"* lands even harder because Time Machine is something Mac
users actually understand.

### credentials.yaml (28 lines, 1 rule) — **survives in design, needs new tables**

The rule's logic — "compare the reader against the owner; Chrome reading Chrome's
password store is Chrome working" — is platform-independent and good. Only
`credentialPaths` changes: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube` are
already in the list and are *already the POSIX paths*; browser profiles move to
`~/.config/google-chrome/...` and `~/.mozilla/...` on Linux, `~/Library/...` on
macOS.

**macOS has one significant advantage:** the Keychain. Credential access there is not
a file read but a Security-framework call, and EndpointSecurity has no direct event
for it — so the highest-value credential store on the platform is partly invisible,
while the file-based ones (SSH keys, cloud credentials, browser profiles) are covered.
Worth stating rather than glossing.

### Summary

| Pack | Linux | macOS |
|---|---|---|
| C2 | 4 of 6 rules; narratives need rewriting; no AV to recommend | 6 of 6; narratives need rewriting |
| Persistence | ~1.5 of 4; **rewrite** | 2 of 4 plus a good new dylib-injection rule; **rewrite** |
| Ransomware | 3 of 3; new tables; weak backup-destruction rule | 3 of 3; **stronger** backup-destruction rule |
| Credentials | 1 of 1; new tables | 1 of 1; new tables; Keychain blind spot |

**macOS carries the product's value across better than Linux does** — chiefly
because it has code signing, which is the single thing Linux cannot give us.

---

## Part 5 — Effort estimates

One engineer, familiar with this codebase, no parallelism. Ranges are honest, not
padded; the wide ones are wide because the risk is real.

### Linux (eBPF, kernel 5.8+ with native BTF)

| # | Workstream | Weeks |
|---|---|---|
| L1 | eBPF sensor: exec/fork tracepoints, connect, file events; bpf2go pipeline; ring-buffer loss detection; per-CPU scratch for paths | 5–7 |
| L2 | Trust substitute for code signing (package-manager provenance) — **highest risk** | 2–3 |
| L3 | Persistence: scanner for the user-level location set, new `Kind` taxonomy, detectors, undo allowlist | 2–3 |
| L4 | Platform layer: `/proc` process table, capability checks, `xdg-open`, D-Bus notifications | 1 |
| L5 | Path/classification rewrite: `filewatch`, XDG dirs, credential paths, shells map, narrate | 1–1.5 |
| L6 | Response executor: signal-based kill, nftables block, quarantine, autostart removal + POSIX-correct undo validation | 1.5–2 |
| L7 | Rule-pack rewrite and narrative translation | 1 |
| L8 | Packaging: systemd unit, `.deb`/`.rpm`, privilege model, install UX | 1–1.5 |
| L9 | Soak, false-positive tuning on real Linux desktops | 2–3 |
| | **Total** | **17–23** |

Add 2–4 weeks if the DNS gap is judged unacceptable and a tc-based passive DNS
capture is attempted. Add 2–3 weeks if a BTF-blob matrix is required for older LTS
distros.

### macOS (EndpointSecurity + NetworkExtension, entitlement granted)

| # | Workstream | Weeks |
|---|---|---|
| M0 | **Entitlement application, Apple Developer org account, D-U-N-S** | 1 of work + **3–12 months of waiting**; **may fail outright** |
| M1 | ES client: native Obj-C/Swift shim, NOTIFY-only, XPC bridge to the Go agent, app-bundle-wrapped daemon via `SMAppService`, FDA flow | 5–8 |
| M2 | NE content-filter sysex for flow visibility with `sourceAppAuditToken` attribution | 3–4 |
| M3 | Platform layer: libproc, `SecStaticCode` signature verification, UserNotifications | 2 |
| M4 | Persistence: LaunchAgents/Daemons, login items, `SMAppService`, BTM, cron; detectors; undo allowlist | 2–3 |
| M5 | Path/classification rewrite | 1–1.5 |
| M6 | Response executor: kill, NE-based block, quarantine, launchd unload | 2 |
| M7 | Rule-pack rewrite | 1 |
| M8 | Signing, notarization, `.pkg`, sysex + FDA approval UX | 2–3 |
| M9 | Soak, false-positive tuning | 2–3 |
| | **Total (excluding M0 wait)** | **20–28** |

**Reduced-scope macOS, no EndpointSecurity entitlement, shippable:** M2 + M3 + M5 +
M8 + a reduced M9 ≈ **8–11 weeks**. Delivers the connection ledger and "Who's
talking?" with real process attribution and no entitlement risk. Competes directly
with LuLu, which is free.

**`eslogger`-based prototype, no entitlement, not shippable:** ≈ **3–4 weeks** on top
of the reduced scope. Adds real exec, file and persistence events from
`sudo eslogger`, which is enough to prove the causal graph and measure the
false-positive rate on real Mac telemetry. Apple disclaims it for application use, so
this is a validation vehicle, not a product — but it means **the entitlement wait
does not have to be idle time**, and it converts M1 from a leap into a swap of the
event source behind an already-proven `EventSource`.

### What is *not* in these numbers

Ongoing cost. Every future NiteWatch feature would need implementing two or three
times, its narrative writing two or three times, and its false-positive profile
measuring on two or three platforms. The second platform roughly doubles the marginal
cost of everything after it. For a solo-engineer product portfolio with 17 active
projects, that is the number that should worry us most.

---

## Part 6 — Recommendation

### Neither, yet.

The Windows product is not finished. From `known-limitations.md` and the 2026-07-25
QA sweep, all of these are open and all are launch blockers:

- **Unsigned binary.** SmartScreen and AV will flag it.
- **No installer, no service, no auto-update.** It is a hand-started console app.
- **The database and API token live beside the executable**, which is a
  same-user tamper risk that the doc explicitly says "is an installer concern and the
  installer does not exist yet."
- **The false-positive rate is unmeasured.** The doc calls this "the number that
  decides whether the tuning is right." The design doc makes a week-long quiet-machine
  soak with zero alerts a first-class test target. It has not been run.
- **Rule packs are neither signed nor hot-loaded**, both of which the design
  promised.
- **Feed licensing is unresolved** and sitting with counsel; two feeds have already
  been removed after their CC0 grants were withdrawn.

Every one of those is cheaper to fix once than twice. The false-positive number in
particular is *the* open question for the product's viability, and porting before
measuring it means potentially building three copies of a tuning model that turns out
to be wrong.

There is also an honest positioning argument. The product's whole stance is not
overclaiming. Shipping a Linux build whose noise control is inert and whose
domain-naming works intermittently, or a macOS build gated on an approval we have not
requested, would be a claim we cannot fully back.

### If a port is greenlit anyway: Linux first, macOS second

**Why Linux first, despite the smaller market:**

- No external gatekeeper. Every Linux blocker is ours to solve; the macOS blocker
  belongs to Apple and is not forecastable.
- It preserves CGO-free and the single static binary. macOS does not.
- It preserves cross-compilation from the WSL2 dev box. macOS requires Mac hardware
  and Xcode in the pipeline.
- Its hardest problem (a trust substitute for code signing) is interesting work with
  a bounded cost, not a coin flip.
- Sequencing Linux first *also* de-risks macOS, because it forces the Windows
  assumptions out of the core — after which the macOS port is mostly the sensor
  bridge.

**Why macOS second despite the better market:** the entitlement. Roughly 16% of
desktops versus 4% is a strong pull, and macOS carries the product's value across
better (code signing works, Time Machine destruction is a great rule, the persistence
model is cleaner). But the downside case is spending six months and being told no,
with no appeal and no enterprise fallback.

**The counter-argument, and it is a real one.** The `eslogger` and content-filter
findings (Sections 3.2–3.3) mean the macOS downside is not actually "six months
wasted." A no from Apple leaves a shippable connection-ledger product built on an
ungated entitlement, plus a validated causal graph. That is a much better failure
mode than it first appears, and if Kevin weighs 16% of desktops heavily enough,
macOS-first is defensible — *provided* the entitlement request goes in on day one
and the work is sequenced content-filter → eslogger prototype → ES swap, so that
every stage has standalone value. It still does not beat "finish Windows first."

### Do this now, regardless

1. **Finish Windows v1.** Signing, installer, service, ProgramData with an ACL, then
   the week-long quiet-machine soak. That soak result should gate any port decision.
2. **Submit the EndpointSecurity entitlement request now.** ~1 week of admin, $99, a
   D-U-N-S number, submitted by the Account Holder. Reported waits run 3–12 months,
   so the queue is the long pole and starting it costs almost nothing. It converts
   the single largest unknown in this document into a fact long before we would need
   the answer. Ask explicitly for **distribution**, not just development, and treat a
   development-only grant as a red flag rather than a green light.
3. **Amend CLAUDE.md's "no kernel driver" rule** to say what it protects (Section
   2.1), so the eBPF question is settled on the merits rather than on wording.
4. **Do not pre-emptively refactor the core for portability.** The seam is already
   good. Extracting platform interfaces before a port is committed is speculative
   generality with a real cost and no certain payoff; do it as the first task of
   whichever port is greenlit.

### What would change this recommendation

- **The Windows soak comes back clean and the product ships and sells.** Then breadth
  is a growth question rather than a distraction, and the ordering above applies.
- **Apple grants distribution entitlement quickly and unconditionally.** That removes
  the single biggest macOS risk and makes macOS-first defensible on market size.
- **A partner or customer with a Linux fleet appears.** That reframes Linux from
  consumer TAM (marginal) to a specific paying deployment (where technical users and
  root daemons are normal), which is a much better fit for what the Linux port can
  actually deliver.
- **Someone finds a workable per-process DNS vantage point on Linux.** That would
  restore the feature the product is built around and materially change the Linux
  value proposition.

---

## Open questions and unconfirmed claims

Listed so nobody treats an estimate as a fact.

1. **Apple's approval odds for `endpoint-security.client`.** Unknowable from outside
   Apple. Resolved by: submitting the request.
2. **Whether Apple would grant *distribution* as well as development.** Documented
   cases exist of the former without the latter. Resolved by: submitting the request
   and reading the grant email carefully.
3. **`CGO_ENABLED=0` with `cilium/ebpf`.** Strongly implied by first-party docs and
   confirmed by third-party recipes, not by a first-party statement. Resolved by: a
   ten-minute build test.
4. **`proc_pidfdinfo` socket enumeration on macOS 15/26 as root without
   entitlements.** No report of restriction found; no authoritative 2026 confirmation
   either. Resolved by: a thirty-minute test on a current Mac.
5. **Whether `eslogger` still works as described on macOS 26.** Every detailed
   writeup found is Ventura/Sonoma-era. Resolved by: `sudo eslogger --list-events` on
   a current Mac. This one matters — it gates the entire "prototype while waiting"
   plan.
6. **Whether an Individual (rather than Organization) Apple enrollment can be
   granted ES.** No evidence either way. Moot for us — Threat Tape LLC can enroll as
   an Organization — but worth knowing.
7. **Whether `nettop` needs root for all-process visibility.** Man page is silent;
   the "needs root" claim found in search traces to an unrelated Linux tool of the
   same name. Low stakes.
8. **Whether `tmc/apple/endpointsecurity` (the purego, cgo-free ES binding) is
   actually correct.** Autogenerated, zero importers, no evidence of a real run.
   Resolved by: running it in a SIP-off VM and diffing its events against `eslogger`
   output for the same activity. Only worth doing if the native-shim recommendation
   in Section 3.4 is rejected.
9. **Ubuntu's and Debian's kernel lockdown mode under Secure Boot in 2026.** Fedora
   confirmed as `integrity` (eBPF works). Resolved by: testing on a Secure Boot
   machine.
10. **Whether `CAP_SYS_RESOURCE`/`RLIMIT_MEMLOCK` is still needed on kernels < 5.11.**
    Likely but unverified. Moot if the floor is set at 5.8+ with native BTF and the
    memcg accounting change is taken into account.
11. **Debian's current `unprivileged_bpf_disabled` default.** Not confirmed. Low
    impact — tracing was never available unprivileged regardless.
12. **`elastic/go-libaudit`'s audit-multicast support level** — the only route to
    coexisting with a running auditd. Only matters if eBPF is ruled out.
13. **Whether a package-provenance trust source is good enough to replace code
    signing on Linux.** This is the Linux port's central unknown and cannot be
    resolved by research — only by building a prototype and measuring it against a
    real desktop's process population. **If a Linux port is greenlit, do this first,
    before the sensor**, as a two-week spike with a go/no-go at the end.

---

## Sources

Platform APIs and libraries
- [cilium/ebpf](https://github.com/cilium/ebpf) · [bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) · [getting started](https://ebpf-go.dev/guides/getting-started/) · [portable eBPF](https://ebpf-go.dev/guides/portable-ebpf/)
- [aquasecurity/libbpfgo](https://github.com/aquasecurity/libbpfgo) · [BTFHub supported distros](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md)
- [elastic/go-libaudit](https://github.com/elastic/go-libaudit) · [sock_diag(7)](https://man7.org/linux/man-pages/man7/sock_diag.7.html) · [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html) · [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
- [mdaverde, Introduction to CAP_BPF](https://www.mdaverde.com/posts/cap-bpf/) · [LWN, A crop of new capabilities](https://lwn.net/Articles/822362/)
- [Ubuntu: unprivileged eBPF disabled by default](https://discourse.ubuntu.com/t/unprivileged-ebpf-disabled-by-default-for-ubuntu-20-04-lts-18-04-lts-16-04-esm/27047) · [SUSE hardening KB](https://support.scc.suse.com/s/kb/Security-Hardening-Use-of-eBPF-by-unprivileged-users-has-been-disabled-by-default)
- [Harouni, eBPF, kernel lockdown and flexibility](https://djalal.opendz.org/post/ebpf-kernel-image-lockdown-and-ebpf-flexibility/)
- [Trail of Bits, Pitfalls of relying on eBPF for security monitoring](https://blog.trailofbits.com/2023/09/25/pitfalls-of-relying-on-ebpf-for-security-monitoring-and-some-solutions/)
- [Quarkslab, Defeating eBPF Uprobe Monitoring](https://blog.quarkslab.com/defeating-ebpf-uprobe-monitoring.html) · [pkg.go.dev/net (Go resolver bypasses libc)](https://pkg.go.dev/net) · [DNS over HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS)

macOS
- [Apple Developer Forums 655467 — applying for the ES entitlement](https://developer.apple.com/forums/thread/655467)
- [Apple Developer Forums 820718 — approval odds ("suck it and see")](https://developer.apple.com/forums/thread/820718)
- [Apple Developer Forums 759149 — development granted, distribution denied](https://developer.apple.com/forums/thread/759149)
- [Apple Developer Forums 767311 — 3 months to approve dev, 3 more to deny distribution; boilerplate rejection](https://developer.apple.com/forums/thread/767311) · [133494](https://developer.apple.com/forums/thread/133494) · [736042](https://developer.apple.com/forums/thread/736042)
- [Apple Developer Forums 791996 — ES as a daemon, not a system extension](https://developer.apple.com/forums/thread/791996) · [804548 — Full Disk Access on unmanaged Macs](https://developer.apple.com/forums/thread/804548)
- [Apple Developer Forums 816877 — no approval process for NetworkExtension](https://developer.apple.com/forums/thread/816877)
- [Apple Developer Forums 775520 — networking entitlements and the hardened runtime](https://developer.apple.com/forums/thread/775520) · [728731 — libproc socket enumeration](https://developer.apple.com/forums/thread/728731)
- [Capability Requests (Account-Holder only)](https://developer.apple.com/help/account/capabilities/capability-requests/) · [System Extensions and DriverKit (SIP-off testing while in review)](https://developer.apple.com/system-extensions/)
- [NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider) · [TN3134 — NE provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) · [Signing a daemon with a restricted entitlement](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement)
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) · [D-U-N-S requirement](https://developer.apple.com/help/account/membership/D-U-N-S) · [Program enrollment](https://developer.apple.com/programs/enroll/)
- [eslogger(1)](https://keith.github.io/xcode-man-pages/eslogger.1.html) · [Cybereason, Blue teaming on macOS with eslogger](https://www.cybereason.com/blog/blue-teaming-on-macos-with-eslogger) · [tstromberg/esl](https://github.com/tstromberg/esl)
- [auditd(8) — OpenBSM deprecated](https://keith.github.io/xcode-man-pages/auditd.8.html) · [Der Flounder, re-enabling OpenBSM on Sonoma](https://derflounder.wordpress.com/2023/10/18/re-enabling-openbsm-auditing-on-macos-sonoma/)
- [tmc/apple/endpointsecurity (purego, cgo-free)](https://pkg.go.dev/github.com/tmc/apple/endpointsecurity) · [ebitengine/purego](https://github.com/ebitengine/purego) · [gatkinso/gomac endpointsecurity (stubbed cgo bridge)](https://pkg.go.dev/github.com/gatkinso/gomac/endpointsecurity) · [xorrior/goesf](https://github.com/xorrior/goesf)
- [Fleet, monitoring DNS traffic on macOS](https://fleetdm.com/guides/monitor-dns-traffic-on-macos) · [Steinberger, unified logging privacy](https://steipete.me/posts/2025/logging-privacy-shenanigans)
- [Objective-See LuLu](https://objective-see.org/products/lulu.html) · [Objective-See, ES without the entitlement (SIP off)](https://objective-see.org/blog/blog_0x47.html)

Market and precedent
- [StatCounter desktop OS share, worldwide](https://gs.statcounter.com/os-market-share/desktop/worldwide)
- [CrowdStrike, Installing Falcon Sensor for Linux (eBPF = "user mode")](https://www.crowdstrike.com/tech-hub/endpoint-security/installing-falcon-sensor-for-linux/) · [The New Stack, a wake-up call for eBPF-based endpoint security](https://thenewstack.io/crowdstrike-a-wake-up-call-for-ebpf-based-endpoint-security/)
- [OpenSnitch](https://github.com/evilsocket/opensnitch)

Persistence taxonomy
- MITRE ATT&CK [T1543.002](https://attack.mitre.org/techniques/T1543/002/) · [T1053.003](https://attack.mitre.org/techniques/T1053/003/) · [T1547.013](https://attack.mitre.org/techniques/T1547/013/) · [T1574.006](https://attack.mitre.org/techniques/T1574/006/)
- [Elastic Security Labs, The Grand Finale on Linux Persistence](https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence)
