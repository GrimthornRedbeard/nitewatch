# Threat-Intelligence Feed Licensing — Review for Counsel

**Date:** 2026-07-26
**Prepared for:** legal review (Sparks)
**Product:** NiteWatch — consumer security agent for Windows

> **Superseded premise (2026-07-29).** This memo was written for a *commercial,
> closed-source* product. NiteWatch is now licensed GPL-3.0-or-later, because the
> Windows event-tracing library it links is GPL and that obligation was discovered
> after the first binary was published. Several conclusions below were reached
> under the old premise and need re-reading against the new one — feed data is
> still downloaded at runtime rather than redistributed in the source tree, which
> is the fact most of the analysis turns on, but that is a judgement for counsel
> rather than an assumption to carry forward.

---

## The question being asked

NiteWatch downloads public threat-intelligence lists and matches network
destinations against them **locally on the end user's machine**. The data is
cached on each customer's PC.

**That is redistribution, not merely use.** Every feed below is written for a
network operator fetching data to protect their own network. Almost none of
them contemplate a vendor bundling the data into a product installed on
third-party machines. This distinction — not the free-versus-paid question — is
the actual legal exposure, and it is the thing most worth a written answer from
each provider.

Two deployment models change the analysis and should be decided before launch:

- **Model A (current):** each installed agent fetches the feed directly from the
  provider. Simplest legally (it looks like ordinary use), but violates several
  providers' fetch-rate limits at scale — Spamhaus explicitly warns that
  excessive downloads get the source IP firewalled.
- **Model B:** Threat Tape mirrors the feeds and pushes a merged artifact to
  customers. Solves the rate-limit problem and is operationally better, but is
  unambiguously redistribution and is **not licensed by most of these sources.**

---

## Decisions already taken in code (2026-07-26)

| Feed | Status | Why |
|---|---|---|
| abuse.ch **ThreatFox** | **REMOVED** | CC0 grant withdrawn ~2025-03 |
| abuse.ch **URLhaus** | **REMOVED** | CC0 grant withdrawn ~2024-12 |
| abuse.ch **Feodo Tracker** | Retained | CC0 still published |
| **Emerging Threats Open** (botcc) | **ADDED** | BSD 3-Clause, commercial use explicit |
| **Tor** exit list | Retained, source changed | CC0; moved to CollecTor |

### The finding that prompted this review

NiteWatch was shipping code that downloaded **ThreatFox** and **URLhaus**. Both
previously carried explicit CC0 dedications; URLhaus's said in terms that
commercial use including *"reselling or integration into commercial products"*
was permitted.

**abuse.ch removed those grants** — URLhaus around 2024-12, ThreatFox around
2025-03, MalwareBazaar around 2026-03 — and published an umbrella
[Terms of Use](https://abuse.ch/terms-of-use/) (effective 2025-11-04) under
which:

- §2.1 — access is provided *"only to: Authenticated Users"*
- §3.1 — authenticated users may access *"for not-for-profit purposes"*
- §4 — *"Use of the Platforms by companies, networks, or individuals with
  commercial or for-profit needs may require a paid subscription, which will be
  managed by Spamhaus"*

The legacy unauthenticated export URLs still return data today. **A working URL
is not a licence**, so those feeds were removed rather than relied upon.

**Open question for counsel:** CC0 is irrevocable once validly applied. Data
published *while* the dedication was posted may remain usable even though new
data is not. Whether a ToS blurb constitutes a valid CC0 dedication, and
whether we could rely on a historical snapshot, is a legal call we have not made.

---

## Currently shipped — believed clean

### Emerging Threats Open — `emerging-botcc.rules`
- **Licence:** BSD 3-Clause. [LICENSE](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/LICENSE) · [BSD text](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/BSD-License.txt)
- **Commercial use:** Yes, free. Conditions: reproduce the copyright notice and
  disclaimer in documentation (done — see `NOTICE`); no use of the ET name to
  endorse the product.
- **Two cautions:**
  1. The default `open/` tree **mixes in GPLv2 rules** (sids 1–3464 and
     100000000–100000908). For closed-source products the BSD-only tree at
     `open-nogpl/` is the safe source. We consume only `blockrules/emerging-botcc.rules`,
     which is outside the GPL sid ranges, but this should be confirmed.
  2. The LICENSE grants rights **by Snort SID range**. A bare IP list has no
     SIDs, so the text does not literally reach the `blockrules/` data files.
     Placement implies BSD; **worth one email to Proofpoint for written
     confirmation.**
- **Why this feed:** it is the botnet *command-and-control destination* set —
  the correct data for watching outbound connections (see "wrong-direction
  feeds" below).

### abuse.ch Feodo Tracker
- **Licence:** CC0, still published at
  [feodotracker.abuse.ch/blocklist](https://feodotracker.abuse.ch/blocklist/):
  *"All datasets offered by Feodo Tracker can be used for both, commercial and
  non-commercial purpose without any limitations (CC0)."*
- **Conflict to note:** Feodo Tracker is listed as an "abuse.ch Platform" in the
  umbrella ToU above, which is in direct tension with the page-level CC0. Which
  controls is a genuine legal question.
- **Operational caveat:** the feed appears stale (last updated 2026-03) and the
  recommended list is near-empty. Retained because the grant is clean, not
  because it is currently productive.

### Tor Project exit list
- **Licence:** CC0. *"To the extent possible under law, the Tor Project has
  waived all copyright and related or neighboring rights in the data."*
  ([metrics.torproject.org](https://metrics.torproject.org/))
- **Source changed:** we now pull from **CollecTor**
  (`collector.torproject.org/recent/exit-lists/`) rather than
  `check.torproject.org`, because the CC0 declaration is published on the
  metrics/CollecTor site and `check.torproject.org` carries no licence of its own.
- **Trademark limit — this one bites marketing, not engineering:** per the
  [Tor trademark FAQ](https://www.torproject.org/about/trademark/), the Tor
  marks may not be used *"in, or as a part of, any project or product name"*
  without written authorisation. Describing a feature descriptively ("Tor exit
  node") is the tolerated pattern; naming a product or SKU is not. Branding
  questions go to tor-brand@rt.torproject.org.

---

## Evaluated and rejected

| Source | Problem |
|---|---|
| **abuse.ch ThreatFox / URLhaus / MalwareBazaar** | CC0 grants withdrawn; commercial use routed to paid Spamhaus subscription; auth key now required |
| **Spamhaus DROP** | Terms §3.1: *"Nothing in these Terms shall be construed as granting an assignment or licence"*. DROP-specific pages say free "regardless of business type"; the general [commercial-data FAQ](https://www.spamhaus.org/faqs/commercial-data/) answers *"Can you use Spamhaus Project data for commercial purposes?"* with **"No."** Unreconciled contradiction. Also: attribution required in-product, but §3.2 forbids using the Spamhaus name in commercial materials; and mirroring to customers is redistribution, which §3.1 withholds. |
| **firehol/blocklist-ipsets** | **No licence at all** (GitHub reports `license: null`). `firehol_level1` includes DShield, whose data file header asserts **CC BY-NC-SA 2.5** — NonCommercial bars us, ShareAlike is viral. Actively unsafe as an aggregate. |
| **stamparm/ipsum** | Repo is Unlicense, but that is a *software* dedication and the author cannot dedicate third-party data. Upstream source list is **unpublished**, so licence diligence is impossible. |
| **Team Cymru bogons** | **No licence published** — silent, neither granting nor restricting. Data is a mechanical restatement of IANA/RIR allocations (thin copyright), and Team Cymru's stated purpose is universal adoption. Probably fine; unconfirmed. One email to support@cymru.com would settle it. |
| **Botvrij.eu** | *"You cannot resell the data, neither as an individual package or as part of a larger package."* Direct hit on a paid product. Also abandoned — files stale since 2026-02, most lists now zero bytes. |
| **Blocklist.de** | No licence anywhere on the site; the only copyright statement (Impressum §3) reads restrictively. Also wrong direction (see below). |
| **CINS / CI Army** | No licence. The EULA linked from the site footer is for unrelated appliance software and contains *"This is not free software"* and a prohibition on distributing "with other products (commercial or otherwise) without prior written permission."* |
| **DigitalSide Threat-Intel** | **Dead.** Host unreachable; GitHub mirror last updated 2024-10. Its `LICENSE` file is a mis-committed Bootstrap web-template licence that grants nothing relevant. |

---

## Wrong-direction feeds — an engineering finding, not a legal one

Several popular free IP feeds are **inbound-attack telemetry**: they list hosts
that attacked someone's SSH/SMTP/HTTPservers. NiteWatch watches **outbound**
connections from a consumer PC.

- **Blocklist.de** — pure fail2ban data; these are scanners hammering inbound
  ports that a home router already drops. Matching outbound traffic against it
  yields near-zero true positives and will false-positive on shared hosting and
  CGNAT addresses.
- **CINS / CI Army** — Sentinel IPS attack telemetry, scanner-weighted by
  construction.
- **ET `compromised-ips.txt`** — mixed; only 583 entries. Low yield.

Even if their licences were clean, these would degrade the false-positive
budget without improving detection. `emerging-botcc.rules` is the correct
Emerging Threats file for this product.

---

## Recommended next steps

1. **Confirm with Proofpoint** that `blockrules/*.txt` and `*.rules` data files
   fall under the BSD grant, given the LICENSE scopes rights by SID range.
   *(Highest value — this is our only substantial live feed.)*
2. **Decide Model A vs Model B** (per-endpoint fetch vs Threat Tape mirror).
   Model B needs a redistribution right from every source.
3. **Contact Spamhaus** for written terms on bundling abuse.ch data in a
   shipped product — their public docs do not address caching on customer
   machines, and they are now the commercial licensee for abuse.ch data. This
   would reopen ThreatFox/URLhaus, which are the highest-quality sources here.
4. **Email Team Cymru** (support@cymru.com) asking whether the bogon lists may
   ship inside a commercial endpoint product. Cheap, converts the only real
   ambiguity into a written answer.
5. **Consider CISA advisories** — US Government works, not subject to domestic
   copyright, TLP:CLEAR. Cleanest licence of anything reviewed, and genuine C2
   infrastructure. Downsides: not machine-readable in bulk without joining the
   AIS/TAXII programme, and cisa.gov returns 403 to non-browser clients.
   Constraints: no CISA logo, no endorsement claims, and advisories sometimes
   incorporate third-party copyrighted material.
6. **Ask SANS ISC** (handlers@isc.sans.edu) which controls for DShield: the
   CC BY-NC-SA 2.5 notice inside `block.txt`, or the
   [feeds documentation](https://www.dshield.org/feeds_doc.html) statement that
   *"Do not resell the data. Other commercial uses are allowed."* Only matters
   if we want DShield.

---

## Standing rule for engineering

**Do not add a threat feed without a licence that permits commercial use and
caching on customer machines.** A URL that returns data is not permission.
Record the licence, its URL, and the date checked alongside the source
definition in `agent/internal/intel/feeds.go`, and add any required attribution
to `NOTICE`.
