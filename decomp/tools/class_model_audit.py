#!/usr/bin/env python3
"""Class-model audit: verify oracle layouts against the original binary's RTTI.

The apply-class-model step must never silently choose between disagreeing
models. This audit compares, per class:

  - **oracle sizeof** (MSVC500 compiling the repo's own class declarations —
    `tools.layout_oracle`), against
  - **the original binary's `CRuntimeClass::m_nObjectSize`**
    (`config/rtti_class_oracle.csv`, recovered from Imperialism.exe).

Verdicts:
  verified        — sizes agree: the source declaration reproduces the original
                    object layout under the original compiler; safe to project.
  source_incomplete — oracle < binary: the source class is missing trailing
                    fields; projection BLOCKED until the declaration is finished.
  source_oversized  — oracle > binary: the source class declares MORE than the
                    original object carried; a modelling error, projection BLOCKED.
  no_rtti         — class has no CRuntimeClass in the binary (non-CObject types);
                    oracle-only evidence, projectable with that caveat recorded.

Writes build-msvc500/evidence/class_model_audit.csv. `--strict` fails on any
source_oversized row (a modelling error, unlike the honest source_incomplete
backlog).

  uv run python -m tools.class_model_audit
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def audit(layout_path: Path, rtti_path: Path):
    data = json.loads(layout_path.read_text())
    layouts = data["layouts"]
    rtti = {}
    with open(rtti_path, newline="") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("name") or "").strip()
            size = (row.get("object_size") or "").strip()
            if name and size:
                rtti[name] = int(size, 16)

    rows = []
    for name, lay in sorted(layouts.items()):
        osz = lay.get("size")
        bsz = rtti.get(name)
        if bsz is None:
            verdict = "no_rtti"
        elif osz == bsz:
            verdict = "verified"
        elif osz is not None and osz < bsz:
            verdict = "source_incomplete"
        else:
            verdict = "source_oversized"
        rows.append({
            "name": name, "verdict": verdict,
            "oracle_size": f"0x{osz:x}" if osz is not None else "",
            "binary_size": f"0x{bsz:x}" if bsz is not None else "",
            "delta": (bsz - osz) if (osz is not None and bsz is not None) else "",
        })
    return rows


def main() -> int:
    from tools.common.repo import repo_root_from_file

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--layout", default="build-msvc500/generated/layout_oracle.json")
    p.add_argument("--rtti", default="config/rtti_class_oracle.csv")
    p.add_argument("--out", default="build-msvc500/evidence/class_model_audit.csv")
    p.add_argument("--strict", action="store_true",
                   help="Exit nonzero on any source_oversized class (a modelling error).")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=1)
    rows = audit(repo_root / args.layout, repo_root / args.rtti)

    out = repo_root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["name", "verdict", "oracle_size", "binary_size", "delta"])
        w.writeheader()
        w.writerows(rows)

    counts: dict = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"class-model audit: {len(rows)} records -> {out}")
    print("  " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    oversized = [r for r in rows if r["verdict"] == "source_oversized"]
    for r in oversized[:10]:
        print(f"    OVERSIZED {r['name']}: oracle={r['oracle_size']} binary={r['binary_size']}")
    if args.strict and oversized:
        print(f"strict: {len(oversized)} source_oversized class(es) — modelling errors")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
