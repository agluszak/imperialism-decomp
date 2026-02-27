#!/usr/bin/env python3
"""
Run a compact class-harmonization wave using maintained commands.

Wave steps:
  1) capture progress counters (pre)
  2) retype class this parameters (optional apply)
  3) capture progress counters (post)
  4) emit one summary artifact

Usage:
  uv run impk run_class_harmonization_wave \
    --batch-tag batch780_tvtc_trade \
    --classes TView TControl TradeControl \
    --apply
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from imperialism_re.core.config import default_project_root, resolve_project_root

def run(cmd: list[str]) -> tuple[int, str]:
    print("[run]", " ".join(cmd))
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.stdout:
        print(cp.stdout.strip())
    if cp.stderr:
        print(cp.stderr.strip())
    return cp.returncode, cp.stdout

def parse_progress(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        key, val = parts
        try:
            out[key] = int(val)
        except ValueError:
            continue
    return out

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
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    tmp = root / "tmp_decomp"
    tmp.mkdir(parents=True, exist_ok=True)

    py = sys.executable
    base = [py, "-m", "imperialism_re.cli"]
    summary_txt = tmp / f"{args.batch_tag}_class_harmonization_summary.txt"

    rc, pre_out = run(
        base
        + [
            "count_re_progress",
            str(root),
        ]
    )
    if rc != 0:
        return rc

    rc, _ = run(
        base
        + [
            "apply_class_this_param_types",
            "--project-root",
            str(root),
            "--classes",
            *args.classes,
            "--apply" if args.apply else "--dry-run",
        ]
    )
    if rc != 0:
        return rc

    rc, post_out = run(
        base
        + [
            "count_re_progress",
            str(root),
        ]
    )
    if rc != 0:
        return rc

    pre = parse_progress(pre_out)
    post = parse_progress(post_out)
    all_keys = sorted(set(pre) | set(post))

    lines = [
        f"batch_tag {args.batch_tag}",
        f"apply {int(args.apply)}",
        f"classes {';'.join(args.classes)}",
    ]
    for key in all_keys:
        pv = pre.get(key, 0)
        qv = post.get(key, 0)
        lines.append(f"{key}_pre {pv}")
        lines.append(f"{key}_post {qv}")
        lines.append(f"{key}_delta {qv - pv}")

    summary_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[saved] {summary_txt}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
