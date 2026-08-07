#!/usr/bin/env python3
"""Shrink-aware guard for policy-baseline updates.

Ratchet baselines record debt. Rewriting one is dangerous only when it GROWS
(blessing new debt); a pure shrink is the ratchet working as designed and needs
no human approval. This guard wraps the ``just <gate>-update`` targets: it
snapshots the baseline, runs the update tool, and compares.

  - pure shrink (every row/value of the new baseline already in the old): OK.
  - growth: restore the snapshot and refuse unless ALLOW_POLICY_BASELINE_UPDATE=1.

Shrink semantics by format:
  - ``.csv`` (pipe tables): the new row set is a subset of the old row set.
  - ``.json``: no new keys anywhere, and every numeric leaf <= its old value.

usage:
  baseline_guard.py --wrap <baseline-file> -- <update-cmd> [args...]
  baseline_guard.py --check-shrink <old-file> <new-file>   # exit 0 if pure shrink
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def csv_rows(text: str) -> set[str]:
    return {l for l in text.splitlines() if l.strip() and not l.startswith("#")}


def json_shrunk(old, new) -> bool:
    if isinstance(old, dict) and isinstance(new, dict):
        if set(new) - set(old):
            return False
        return all(json_shrunk(old[k], new[k]) for k in new)
    if isinstance(old, (int, float)) and isinstance(new, (int, float)):
        return new <= old
    if isinstance(old, list) and isinstance(new, list):
        # list baselines are row-set-like: no new entries
        old_set = {json.dumps(x, sort_keys=True) for x in old}
        return all(json.dumps(x, sort_keys=True) in old_set for x in new)
    return old == new


def is_pure_shrink(old_text: str, new_text: str, suffix: str) -> bool:
    if suffix == ".json":
        try:
            return json_shrunk(json.loads(old_text), json.loads(new_text))
        except ValueError:
            return False
    new_rows = csv_rows(new_text)
    old_rows = csv_rows(old_text)
    return new_rows <= old_rows


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["--check-shrink"]:
        old_p, new_p = Path(argv[1]), Path(argv[2])
        old = old_p.read_text(encoding="utf-8") if old_p.is_file() else ""
        new = new_p.read_text(encoding="utf-8") if new_p.is_file() else ""
        ok = is_pure_shrink(old, new, new_p.suffix or old_p.suffix)
        print("pure-shrink" if ok else "growth")
        return 0 if ok else 1

    assert argv[:1] == ["--wrap"] and "--" in argv, __doc__
    baseline = Path(argv[1])
    cmd = argv[argv.index("--") + 1 :]
    old = baseline.read_text(encoding="utf-8") if baseline.is_file() else ""

    rc = subprocess.run(cmd).returncode
    if rc != 0:
        return rc
    new = baseline.read_text(encoding="utf-8") if baseline.is_file() else ""

    if is_pure_shrink(old, new, baseline.suffix):
        print(f"[baseline-guard] pure shrink of {baseline.name} — no approval needed.")
        return 0
    if os.environ.get("ALLOW_POLICY_BASELINE_UPDATE") == "1":
        print(f"[baseline-guard] {baseline.name} GREW — allowed by explicit approval.")
        return 0
    baseline.write_text(old, encoding="utf-8")
    print("REFUSED: this update GROWS the policy baseline (blessing new debt);")
    print("the previous baseline was restored. If a human approved the exception,")
    print("rerun with ALLOW_POLICY_BASELINE_UPDATE=1. (Pure shrinks pass freely.)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
