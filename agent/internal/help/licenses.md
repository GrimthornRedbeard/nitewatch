# NiteWatch — Copyright and Licences

**Copyright © 2026 Threat Tape LLC.** All rights reserved, and then most of them
given back — see below.

This document is compiled into the binary rather than kept on a website,
because the terms that apply to you are the terms of the copy you are actually
running.

---

## NiteWatch is free software

NiteWatch is licensed under the **GNU General Public License, version 3 or (at
your option) any later version**.

That means you may run it for any purpose, read the source, change it, and pass
it on — including a changed version — provided you pass on the same freedoms.
If you distribute NiteWatch or anything built from it, you must make the
corresponding source available under the GPL as well.

**There is no warranty.** Not a limited one. To the extent permitted by law,
this program is provided WITHOUT ANY WARRANTY — without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. The full
disclaimer is in the licence text, and a plainer one is in the notice you
accepted when you first opened this dashboard.

The complete licence text ships with the source. If you did not receive a copy,
see <https://www.gnu.org/licenses/gpl-3.0.html>.

### Where the source is

<https://github.com/GrimthornRedbeard/nitewatch>

Every released build is tagged there, and the version shown in this panel names
the exact commit it was built from. If that repository is ever unreachable,
email **threattape@gmail.com** and the corresponding source for your version
will be sent to you.

### Why GPL, since you may wonder

Honestly? Because the Windows event-tracing library NiteWatch depends on is
GPL-licensed, and linking it into this program makes this program GPL too.
Discovering that after publishing a binary is a good argument for reading your
dependencies' licences before you ship rather than after.

It is not a decision I regret. A security tool asking you to trust its judgement
about your own computer is in a poor position to refuse to show you how it
reaches that judgement.

---

## Third-party software in this binary

### GNU General Public License v3

- **github.com/0xrawsec/golang-etw** — the Windows event-tracing consumer. This
  is the dependency whose licence sets the licence of the whole program.
- **github.com/0xrawsec/golang-utils** — supporting utilities used by the above.

### MIT License

- **github.com/ShaneDolphin/gorapide** — the causal event graph (partially
  ordered set, logical clocks, pattern matching) that produces the "what led to
  this" chains.

  > Copyright (c) 2026 Beautiful Majestic Dolphin LLC
  >
  > Permission is hereby granted, free of charge, to any person obtaining a copy
  > of this software and associated documentation files (the "Software"), to deal
  > in the Software without restriction, including without limitation the rights
  > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  > copies of the Software, and to permit persons to whom the Software is
  > furnished to do so, subject to the following conditions:
  >
  > The above copyright notice and this permission notice shall be included in all
  > copies or substantial portions of the Software.
  >
  > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  > SOFTWARE.

### BSD 3-Clause

- **golang.org/x/sys** — Windows system call bindings. Copyright (c) 2009 The Go
  Authors.
- **modernc.org/sqlite** and **modernc.org/libc** — the pure-Go SQLite used for
  the connection ledger, which is why this program needs no C toolchain and no
  installer. Copyright (c) 2017 The Sqlite Authors / The Libc Authors.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the conditions of the BSD 3-Clause
  licence are met, including reproduction of the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution, and that neither the name of
  the copyright holder nor the names of its contributors may be used to endorse
  or promote products derived from this software without specific prior written
  permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.

Full licence texts for every dependency ship with the source, in the Go module
cache of any checkout.

---

## Threat-intelligence data

NiteWatch matches network destinations against public threat-intelligence data
downloaded to, and cached on, your own machine. The following notices are
required by the terms under which that data is provided.

### Emerging Threats Open (Proofpoint)

Botnet command-and-control indicators are sourced from the Emerging Threats Open
ruleset.

> Copyright (c) 2003-2026, Emerging Threats. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the above copyright notice, this
> list of conditions and the following disclaimer are reproduced.

### abuse.ch

Where enabled, indicators may be sourced from abuse.ch projects (ThreatFox,
Feodo Tracker, URLhaus), which are provided for use without warranty.

Feed sources are pulled down whole and matched locally. **No address from your
machine is ever sent to a feed provider** — see the privacy section of the known
limitations for the two features that can contact a third party, both of which
require you to press a button first.

---

## Questions

**threattape@gmail.com.** Including "am I allowed to do X with this?", which is
usually answered by "yes, if whatever you pass on carries the same freedoms".
