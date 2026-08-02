# Copyright (C) 2026 Threat Tape LLC
# SPDX-License-Identifier: GPL-3.0-or-later
"""Summarise a soak run into something small enough to hand to somebody else.

    python3 soak-report.py nitewatch.db [nitewatch.log] > soak-report.txt

The connection ledger is a complete record of everywhere a machine has been.
Handing the whole database to another person means handing over that, plus the
file paths and program names of everything installed. This produces the part
that is actually needed to judge false positives — the alerts, what fired them,
and enough context to see whether each one was right — and nothing else.

Read the output before you send it. That is the point of it being a file.
"""
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict

USER = re.compile(r"([A-Za-z]:\\Users\\)([^\\\s\"]+)", re.I)


def redact(text):
    """Replace the Windows account name. Paths stay: they are most of what
    makes an alert judgeable."""
    return USER.sub(lambda m: m.group(1) + "<user>", text or "")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    db = sqlite3.connect(sys.argv[1])
    db.row_factory = sqlite3.Row

    out = print
    out("NiteWatch soak report")
    out("=" * 60)

    if len(sys.argv) > 2:
        try:
            with open(sys.argv[2], encoding="utf-8", errors="replace") as fh:
                log = fh.read()
        except OSError as e:
            log = ""
            out("could not read the log: %s" % e)
        if log:
            for line in log.splitlines():
                if "NiteWatch agent" in line:
                    out("build:      %s" % line.split("NiteWatch agent")[-1].strip())
                    break
            # The failures worth knowing about before reading any numbers.
            bad = [l for l in log.splitlines() if re.search(
                r"FAILING|panic|fatal|sensor unavailable|could not", l, re.I)]
            if bad:
                out("")
                out("PROBLEMS IN THE LOG (%d)" % len(bad))
                for l in bad[:15]:
                    out("  %s" % l.strip()[:150])

    # ---- span ---------------------------------------------------------
    row = db.execute(
        "SELECT MIN(ts) a, MAX(ts) b, COUNT(*) n FROM connections").fetchone()
    out("")
    out("ledger:     %s connections, %s → %s" % (row["n"], row["a"], row["b"]))
    procs = db.execute(
        "SELECT COUNT(DISTINCT image) n FROM connections").fetchone()["n"]
    dests = db.execute(
        "SELECT COUNT(DISTINCT COALESCE(NULLIF(domain,''), remote_ip)) n "
        "FROM connections").fetchone()["n"]
    out("            %d distinct programs, %d distinct destinations" % (procs, dests))

    # ---- the number that matters --------------------------------------
    alerts = db.execute("SELECT * FROM alerts ORDER BY ts").fetchall()
    drills = [a for a in alerts if "drill" in (a["evidence"] or "").lower()
              or (a["rule_id"] or "").startswith("selftest")]
    real = [a for a in alerts if a not in drills]

    out("")
    out("ALERTS: %d total (%d from the Test-me drill, %d from live activity)"
        % (len(alerts), len(drills), len(real)))
    out("")
    if not real:
        out("  Nothing fired. That is the target.")
    else:
        by_rule = Counter(a["rule_id"] for a in real)
        by_sev = Counter(a["severity"] for a in real)
        out("  by severity: %s" % ", ".join(
            "%s=%d" % (s, n) for s, n in by_sev.most_common()))
        out("")
        out("  by rule:")
        for rule, n in by_rule.most_common():
            out("    %-34s %4d" % (rule, n))

        # Which programs, so a pattern shows without reading every alert.
        out("")
        out("  programs named, by rule:")
        named = defaultdict(Counter)
        for a in real:
            try:
                ev = json.loads(a["evidence"] or "{}")
            except ValueError:
                ev = {}
            img = ev.get("ImagePath") or ev.get("Target") or ev.get("TargetPath") or "?"
            named[a["rule_id"]][redact(img).split("\\")[-1]] += 1
        for rule, progs in named.items():
            out("    %s" % rule)
            for p, n in progs.most_common(8):
                out("        %-40s %4d" % (p[:40], n))

    # ---- the bodies, which is where wrongness shows -------------------
    out("")
    out("=" * 60)
    out("EVERY LIVE ALERT, IN FULL")
    out("=" * 60)
    for a in real:
        out("")
        out("[%s] %s  (%s)" % (a["severity"].upper(), a["ts"], a["rule_id"]))
        out("  %s" % redact(a["title"]))
        for line in redact(a["narrative"]).splitlines():
            if line.strip():
                out("      %s" % line.strip())
        try:
            ev = json.loads(a["evidence"] or "{}")
        except ValueError:
            ev = {}
        ctx = ev.get("Context") or {}
        if ctx.get("lineage"):
            out("      chain: %s" % redact(" -> ".join(ctx["lineage"])))
        for act in (ctx.get("recent") or [])[:8]:
            detail = redact(act.get("detail", ""))
            out("        - %s %s%s" % (act.get("kind", ""), detail[:90],
                                       " x%d" % act["count"] if act.get("count", 1) > 1 else ""))

    out("")
    out("=" * 60)
    out("Read this before sending it. Program names, file paths and the")
    out("destinations above describe your machine; the Windows account name")
    out("has been replaced but nothing else has.")


if __name__ == "__main__":
    main()
