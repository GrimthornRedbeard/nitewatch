# NiteWatch — Where This Is Headed

What is built, what is coming, and what is deliberately never coming. No dates:
this is one person's project and a date would be a guess dressed up as a
promise. The order is roughly the order of work.

---

## Built and working

- **The flight recorder.** Every outbound connection, attributed to the program
  that made it, with the destination's owner and country, kept in a searchable
  ledger that is still there tomorrow.
- **The causal graph.** Not just what happened but what *caused* what, so any
  connection can be traced back through the program, its parent, the lookup
  that produced the address, and the files touched around the same moment.
- **Plain-English stories.** That chain, written as a sentence a person can
  read, with every clause grounded in an observed event.
- **Detection.** Fourteen rules across four packs — command-and-control,
  persistence, ransomware, credential theft — each one shipping its own
  hand-written explanation and numbered playbook.
- **One-click response.** Stop a program, block an address, quarantine a file,
  remove a startup entry. Every one behind an explicit click, with undo where
  the operating system allows it.
- **Who owns this?** On-demand registration lookup for a destination, and an
  optional VirusTotal check on a program's fingerprint. Both off by default,
  both requiring a press, neither ever automatic.
- **Explain everything.** A plain-English layer describing common programs and
  defining the jargon, for anyone who does not work in this field.
- **Test me.** Fires every alert the product can raise, so "is this thing
  working?" has an answer that takes one click.

---

## Next

These are what stand between the current state and something worth installing
on somebody else's machine.

- **Code signing.** The single biggest one. Right now Windows SmartScreen warns
  about NiteWatch and is entirely right to. Until the binary is signed, asking
  anyone to run it means asking them to ignore a warning that exists for good
  reason — which is a bad habit to teach.
- **An installer, and running as a service.** Today it is a console application
  started by hand, which means it is not watching when you are not looking.
- **A measured false-positive rate.** The number that decides whether the tuning
  is right, and it does not exist yet. It needs a week of quiet running on real
  machines. Nothing else on this list matters if the product cries wolf.
- **The database somewhere sensible.** It currently sits beside the executable.
  It belongs in `%ProgramData%` with an access-control list, which is an
  installer's job and therefore waits on the installer.

---

## Later

- **Signed rule packs, loaded without a restart**, so detections can improve
  without shipping a whole new binary.
- **A tray icon**, so the agent is visible and reachable without opening a
  browser.
- **A proper local security boundary.** The dashboard is guarded by a token over
  loopback, which stops other user accounts and opportunistic malware but cannot
  identify a caller running as you. A named pipe with an access-control list is
  the right answer.
- **Richer telemetry.** Command lines and file hashes would enable a whole class
  of detection that is currently impossible, because the raw Windows event
  source does not supply either. That likely means optionally reading Sysmon
  where it is installed.
- **Threat-feed licensing resolved.** Several good sources cannot be used
  commercially without written permission, and caching feed data on a customer's
  machine is redistribution rather than use.
- **A real false-positive test suite** — a recorded week of ordinary desktop
  activity, replayed on every change, with the alert count as a build gate.

---

## Never

Not "not yet". These are decisions, and reopening one would make this a
different product.

- **No kernel driver.** Blocking something *before* it happens means sitting in
  the path of every operation, in the kernel, where a bug is a blue screen or a
  privilege-escalation hole rather than a crashed application. NiteWatch watches
  and advises; it does not stand in the way. Where blocking is genuinely useful
  — network destinations — it is done through the firewall Windows already
  ships, whose kernel component is Microsoft's problem and not mine.
- **No automatic response.** Nothing is ever stopped, blocked or quarantined
  without a person pressing a button. A false positive that kills a process you
  needed is worse than the malware it was guessing at.
- **Nothing about your machine is uploaded.** Threat intelligence is downloaded
  whole and matched locally. The two features that ask a third party anything —
  the registration lookup and the VirusTotal check — send one address or one
  fingerprint, only when you press the button, and say so before you do.
- **Windows only.** macOS and Linux were properly assessed and taken off the
  roadmap. Linux cannot reliably tell you *which program* made a DNS lookup,
  which is the whole point of the product, and macOS needs an Apple entitlement
  nobody can promise you will get.
- **No LLM in the alert path.** Every word of every alert is written by a person
  in advance and shipped in the rule file beside the logic that fires it.
  Security advice generated on the fly is confident, fluent and occasionally
  wrong, which is the worst possible combination.

---

## Telling me I have this wrong

The order above is a judgement, not a decree, and it is very likely wrong in
places. If something here matters more to you than the thing above it — or if
there is an obvious gap — say so: **threattape@gmail.com**.
