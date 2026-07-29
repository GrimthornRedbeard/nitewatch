# Reporting a security problem in NiteWatch

**threattape@gmail.com.** No form, no portal, no PGP gymnastics unless you want
them — say what you found and how you found it.

There is no bug bounty. This is one person's pre-release project and there is no
money behind it. If that changes, this page changes.

## What I would very much like to hear about

NiteWatch reads kernel telemetry, opens a local network listener, and can stop
processes, quarantine files and write firewall rules. The interesting failures
are the ones where that power ends up in the wrong hands:

- **Anything that reaches the local API without the token.** It binds 127.0.0.1,
  validates the `Host` header against DNS rebinding, and requires a token stored
  owner-readable on disk. A way around any of that is the report I most want.
- **A page on the internet causing NiteWatch to act.** Remediation endpoints are
  POST-only and guarded for exactly this reason. A cross-site request that stops
  a process or writes a rule is a serious bug.
- **Quarantine escaping its directory**, or a crafted path causing a write
  outside it.
- **Anything that makes the agent attack the machine it is watching** — a
  remediation acting on the wrong target, a path traversal in the file watcher,
  a crash that leaves a firewall rule half-written.
- **Privilege problems.** It runs elevated, because ETW requires it. Anything
  that lets an unprivileged process on the same machine use that.

## Also worth reporting, and easy to overlook

- **A rule that can be made to fire by a remote party.** A detection that a
  website or an email can trigger is a denial-of-service against the user's
  attention, and attention is the thing this product spends.
- **Anything that leaks what the machine has been doing.** The privacy claims
  are specific: nothing about the machine leaves it unless the user presses a
  button that says what it will send. A path that breaks that promise is a
  security bug even if nothing crashes.

## What is already known and not worth reporting

Read **Known Limitations** first — it is compiled into the binary, one click
from the dashboard, and it is candid. In particular:

- The binary is **unsigned**. Windows will warn; Smart App Control will refuse.
  That is a documented decision, not an oversight.
- There is **no kernel driver**, so nothing is blocked before it happens. That
  is the architecture, permanently.
- The **false-positive rate is unmeasured**. False alarms are expected right now
  and I want them — but as bug reports, not security reports.

## What happens after you send it

I will confirm I received it. I will tell you honestly whether I understand it
and roughly when I can fix it, and if the answer is "not soon" you will get that
answer rather than silence.

Please give me a reasonable window before publishing. I am not going to name a
number of days and pretend it is a policy — if you have found something serious
and I go quiet on you, publish it. A tool nobody can trust to fix its own holes
does not deserve the benefit of the doubt.

Credit in the release notes if you want it, and in the contributor credits.
Say so either way.
