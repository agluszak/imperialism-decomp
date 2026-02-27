#!/usr/bin/env python3
"""
Run a compact class-harmonization wave.

Wave steps:
  1) inventory root-stub this-types (pre)
  2) retarget class this pointer types (optional apply)
  3) normalize redundant this,pThis signatures (optional apply)
  4) inventory root-stub this-types (post)

Usage:
  .venv/bin/python new_scripts/run_class_harmonization_wave.py \
    --batch-tag batch780_tvtc_trade \
    --classes TView TControl TradeControl \
    --apply
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


def run(cmd: list[str]) -> int:
    print("[run]", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.stdout:
        print(cp.stdout.strip())
    if cp.stderr:
        print(cp.stderr.strip())
    return cp.returncode


def rows_in_csv(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", newline="") as fh:
        n = sum(1 for _ in fh)
    return max(0, n - 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-tag", required=True, help="Artifact prefix tag")
    ap.add_argument("--classes", nargs="+", required=True, help="Class names")
    ap.add_argument(
        "--class-regex",
        default="",
        help="Optional class regex for inventory filtering (default auto-built from --classes)",
    )
    ap.add_argument("--apply", action="store_true", help="Apply retarget + normalize")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    tmp = root / "tmp_decomp"
    tmp.mkdir(parents=True, exist_ok=True)

    py = str(root / ".venv" / "bin" / "python")
    class_regex = args.class_regex
    if not class_regex:
        class_regex = "^(" + "|".join(args.classes) + ")$"

    pre_csv = tmp / f"{args.batch_tag}_root_stub_pre.csv"
    post_csv = tmp / f"{args.batch_tag}_root_stub_post.csv"

    inv_script = str(root / "new_scripts" / "inventory_root_stub_this_types.py")
    retarget_script = str(root / "new_scripts" / "retarget_class_this_pointer_types.py")
    norm_script = str(root / "new_scripts" / "normalize_thiscall_redundant_pthis.py")

    rc = run(
        [
            py,
            inv_script,
            "--project-root",
            str(root),
            "--class-regex",
            class_regex,
            "--out-csv",
            str(pre_csv),
        ]
    )
    if rc != 0:
        return rc

    rc = run(
        [
            py,
            retarget_script,
            "--project-root",
            str(root),
            "--classes",
            *args.classes,
            "--apply" if args.apply else "--dry-run",
        ]
    )
    if rc != 0:
        return rc
    if args.apply:
        time.sleep(1)

    if args.apply:
        rc = run([py, norm_script, "--project-root", str(root), "--apply"])
    else:
        rc = run([py, norm_script, "--project-root", str(root)])
    if rc != 0:
        return rc
    if args.apply:
        time.sleep(1)

    rc = run(
        [
            py,
            inv_script,
            "--project-root",
            str(root),
            "--class-regex",
            class_regex,
            "--out-csv",
            str(post_csv),
        ]
    )
    if rc != 0:
        return rc

    pre_rows = rows_in_csv(pre_csv)
    post_rows = rows_in_csv(post_csv)
    print(f"[summary] pre_rows={pre_rows} post_rows={post_rows} delta={post_rows - pre_rows}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
