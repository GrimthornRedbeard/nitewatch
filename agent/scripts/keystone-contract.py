#!/usr/bin/env python3
# Copyright (C) 2026 Threat Tape LLC
# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract test: does a NiteWatch Keystone export parse with Keystone's OWN code?

Keystone (the portfolio correlation tier) is a private repository, so this test
cannot live in the Go suite. It copies Keystone's nitewatch connector and its
observation model into a throwaway package — never importing from, or writing
to, the Keystone checkout — and runs them on a real export:

    nitewatch -db nitewatch.db -export-keystone export.json
    python3 scripts/keystone-contract.py export.json ~/Projects/keystone

Needs pydantic (Keystone's observation model uses it).

It fails if any flow or event in the export is silently dropped by Keystone's
parser, or if the observations it produces disagree with the export. A dropped
record is the failure mode that matters: Keystone's parsers skip what they cannot
read rather than raising, so a field renamed on either side shows up as missing
data, never as an error.
"""
import importlib
import json
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def load_keystone(keystone: Path, into: Path):
    for rel in ("server/app/connectors/nitewatch.py", "server/app/models/observation.py"):
        src = keystone / rel
        if not src.is_file():
            sys.exit(f"keystone checkout has no {rel} — has the connector moved?")
        dst = into / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst)
    for pkg in ("server", "server/app", "server/app/connectors", "server/app/models"):
        (into / pkg / "__init__.py").touch()
    sys.path.insert(0, str(into))
    return importlib.import_module("server.app.connectors.nitewatch")


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    export = json.loads(Path(sys.argv[1]).read_text())
    keystone = Path(sys.argv[2]).expanduser()
    failures = []

    if export.get("schema") != "nitewatch.keystone-export/v1":
        failures.append(f"unexpected schema {export.get('schema')!r}")

    with tempfile.TemporaryDirectory() as tmp:
        nw = load_keystone(keystone, Path(tmp))
        when = datetime.now(UTC)

        flows = export["flows"]
        egress = nw.parse_nitewatch_egress(export, when)
        if len(egress) != len(flows):
            failures.append(f"egress: {len(flows)} flows exported, Keystone parsed {len(egress)}")
        for f, o in zip(flows, egress):
            if o.kind != "net.egress" or o.payload != {"src_host": f["src_host"], "dst": f["dst"], "port": f["port"]}:
                failures.append(f"egress mismatch: {f} -> {o.payload}")
            if ("hostname", f["src_host"]) not in o.identifiers:
                failures.append(f"egress: source host not an identifier: {o.identifiers}")
            if any(v == f["dst"] for _, v in o.identifiers):
                failures.append(f"egress: destination leaked into identifiers: {o.identifiers}")

        events = export["events"]
        causal = nw.parse_nitewatch_causal(export, when)
        if len(causal) != len(events):
            failures.append(f"causal: {len(events)} events exported, Keystone parsed {len(causal)}")
        for e, o in zip(events, causal):
            for k in ("src_host", "pid", "image", "parent_pid", "parent_image", "dst", "user_sid"):
                if o.payload.get(k) != e.get(k):
                    failures.append(f"causal {k}: exported {e.get(k)!r}, Keystone read {o.payload.get(k)!r}")
            if o.identifiers:
                failures.append(f"causal: observation must be payload-only, got {o.identifiers}")

        with_parent = sum(1 for e in events if e.get("parent_pid") is not None)
        for s in export["stories"]:
            st = s["story"]
            n = len(st.get("steps", []))
            for edge in st.get("edges", []):
                if not (0 <= edge["from"] < n and 0 <= edge["to"] < n):
                    failures.append(f"story {s['connection_id']}: edge {edge} outside {n} steps")

    print(f"flows: {len(flows)} exported, {len(egress)} parsed as net.egress")
    print(f"events: {len(events)} exported, {len(causal)} parsed as nitewatch.causal "
          f"({with_parent} with a recorded parent)")
    print(f"stories: {len(export['stories'])}")
    if failures:
        print("CONTRACT FAILURES:")
        for f in failures:
            print("  -", f)
        return 1
    print("contract OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
