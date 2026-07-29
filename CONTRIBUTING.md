# Contributing to NiteWatch

Poking and prodding is actively welcome. So is telling me I have got something
wrong — this project has already shipped two bugs where one program's activity
was reported against another's, and both were found by somebody looking at real
output and saying "that cannot be right".

## The most valuable thing you can send

**A false positive.** NiteWatch's whole bet is that a security tool which cries
wolf gets switched off, and a tool that is off catches nothing. The
quiet-machine false-positive rate is the number that decides whether this
product is honest, and it is currently unmeasured.

So if it screamed about a program that was minding its own business, that is
the report I want most. Include:

- **The build.** Open **Limits & roadmap** in the dashboard; the line at the top
  says `Build 0.1.x-pre (abc1234)`. Paste it. A report without it costs more to
  act on than it is worth, because the first question is always "which build?"
- **What the alert said**, in full — the narrative and the "what led to this"
  chain, not just the headline. The chain is usually where the wrongness shows.
- **What your computer was actually doing** at the time. This is the part only
  you know, and it is the part that makes a report fixable.

The dashboard's **Ask about this** button assembles most of that for you and
copies it to your clipboard. It sends nothing anywhere; you paste it wherever
you like, including into an email to me.

## Licence and copyright

NiteWatch is **GPL-3.0-or-later**. Contributions are accepted under the same
terms — inbound equals outbound. You keep the copyright in what you write; you
are licensing it under the GPL, exactly as the project is licensed to you.

There is no CLA and no copyright assignment. That is a deliberate choice with a
real consequence, stated here rather than buried: because contributors retain
their copyright, Threat Tape LLC cannot unilaterally relicense the project
later. Anything you contribute stays free software, and so does everything
built on top of it.

Please add an SPDX header to any new file:

```go
// Copyright (C) 2026 <you or your employer>
// SPDX-License-Identifier: GPL-3.0-or-later
```

## Building it

```bash
cd agent && go test ./...                # the whole suite, on any OS
```

```bash
cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o ../dist/nitewatch.exe ./cmd/nitewatch
```

`-trimpath` matters: released builds have their SHA-256 published, and a build
without it will not match even with identical source.

**You do not need Windows to work on most of this.** The build is CGO-free and
every platform-specific call sits behind a stub, so the suite runs anywhere. You
can drive the whole product on Linux or macOS by replaying a recorded trace:

```bash
cd agent && go run ./cmd/nitewatch --replay ../testdata/traces/malicious.jsonl --serve
```

That is not a convenience — it is the reason the test suite is worth anything.
Code that can only be exercised on Windows does not get exercised. The recycled
file-handle bug survived precisely because its cache lived inside the
Windows-only ETW file where no test could reach it; moving it out was half the
fix.

## Things worth knowing before you propose something

Some decisions are settled, and reopening one would make this a different
product. They are listed under **Never** in the roadmap, inside the app. The
short version:

- **No kernel driver.** Ever, in this product line. Blocking something before it
  happens means sitting in the path of every operation, in the kernel, where a
  bug is a blue screen rather than a crashed application.
- **No automatic response.** Nothing is stopped, blocked or quarantined without
  a person pressing a button.
- **Nothing about the machine is uploaded.** Intelligence is downloaded whole
  and matched locally. The two features that ask a third party anything send one
  address or one file fingerprint, only on an explicit press, and say so first.
- **No LLM in the alert path.** Every word of every alert is written by a person
  in advance and ships in the rule file beside the logic that fires it.
- **Windows only.** macOS and Linux were assessed and taken off the roadmap.

A pull request that quietly crosses one of those lines will get a polite no. One
that argues the line is wrong is a conversation worth having.

## House style

Match the surrounding code. The comments in this project explain *why* something
is the way it is, especially where the obvious approach was tried and failed —
several of them exist specifically so the next person does not reintroduce a bug
that was hard to find. If you fix something subtle, leave that kind of note
behind.

Tests are expected to fail against the bug they describe. If a regression test
passes with the fix reverted, it is not testing what you think.

Questions: **threattape@gmail.com**.
