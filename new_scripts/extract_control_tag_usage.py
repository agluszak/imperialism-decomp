#!/usr/bin/env python3
"""
Extract likely 4-char control-tag immediates used in code.

Outputs:
  1) detailed usage CSV (one row per function/tag, with sample instruction addresses)
  2) summary CSV (one row per tag, with function/use counts)

Usage:
  .venv/bin/python new_scripts/extract_control_tag_usage.py \
    [detail_csv] [summary_csv] [project_root]
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def decode_tag_pair(value: int) -> tuple[str, str] | None:
    """
    Convert 32-bit immediate to 4-char little-endian string if it looks like a tag.
    """
    b0 = value & 0xFF
    b1 = (value >> 8) & 0xFF
    b2 = (value >> 16) & 0xFF
    b3 = (value >> 24) & 0xFF
    bs = bytes((b0, b1, b2, b3))

    # Keep strict ASCII printable range (space..~).
    if any(c < 0x20 or c > 0x7E for c in bs):
        return None

    s_le = bs.decode("ascii")

    # Heuristic: likely tag = at least 3 alnum chars and no punctuation-heavy values.
    alnum = sum(ch.isalnum() for ch in s_le)
    if alnum < 3:
        return None

    # Exclude obvious non-tag patterns.
    if s_le in ("    ", "....", "----", "____", "0000", "1111"):
        return None

    return s_le, s_le[::-1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "detail_csv",
        nargs="?",
        default="tmp_decomp/control_tag_usage_detail.csv",
        help="Detailed usage CSV output path",
    )
    ap.add_argument(
        "summary_csv",
        nargs="?",
        default="tmp_decomp/control_tag_usage_summary.csv",
        help="Summary usage CSV output path",
    )
    ap.add_argument(
        "project_root",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1]),
        help="Ghidra project root path",
    )
    ap.add_argument(
        "--only-unresolved",
        action="store_true",
        help="Scan only unresolved-style names (FUN_* and Cluster_*)",
    )
    ap.add_argument(
        "--name-regex",
        default="",
        help="Optional regex filter for function names",
    )
    args = ap.parse_args()

    detail_csv = Path(args.detail_csv)
    summary_csv = Path(args.summary_csv)
    root = Path(args.project_root)
    name_re = re.compile(args.name_regex) if args.name_regex else None

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    # detail rows keyed by (tag_le, function_entry)
    usage = {}
    # summary counters
    tag_to_functions = defaultdict(set)
    tag_to_hits = defaultdict(int)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            func = fit.next()
            fn_name = func.getName()
            if args.only_unresolved and not (
                fn_name.startswith("FUN_") or fn_name.startswith("Cluster_")
            ):
                continue
            if name_re and not name_re.search(fn_name):
                continue
            fn_ep = str(func.getEntryPoint())
            key_prefix = (fn_ep, fn_name)

            ins_it = listing.getInstructions(func.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                ins_addr = str(ins.getAddress())
                for op_idx in range(ins.getNumOperands()):
                    for obj in ins.getOpObjects(op_idx):
                        try:
                            raw = obj.getValue() if hasattr(obj, "getValue") else None
                        except Exception:
                            raw = None
                        if raw is None:
                            continue
                        value = int(raw) & 0xFFFFFFFF
                        decoded = decode_tag_pair(value)
                        if decoded is None:
                            continue
                        tag_le, tag_be = decoded

                        row_key = (tag_le, fn_ep)
                        if row_key not in usage:
                            usage[row_key] = {
                                "tag_le": tag_le,
                                "tag_be": tag_be,
                                "value_hex": f"0x{value:08x}",
                                "function_addr": f"0x{int(fn_ep, 16):08x}",
                                "function_name": fn_name,
                                "hit_count": 0,
                                "sample_insn_addrs": [],
                            }

                        row = usage[row_key]
                        row["hit_count"] += 1
                        if len(row["sample_insn_addrs"]) < 8:
                            row["sample_insn_addrs"].append(f"0x{int(ins_addr, 16):08x}")

                        tag_to_functions[tag_le].add(key_prefix)
                        tag_to_hits[tag_le] += 1

    detail_rows = sorted(
        usage.values(),
        key=lambda r: (r["tag_le"], -r["hit_count"], r["function_addr"]),
    )

    summary_rows = []
    for tag_le in sorted(tag_to_functions.keys()):
        funcs = tag_to_functions[tag_le]
        tag_be = tag_le[::-1]
        summary_rows.append(
            {
                "tag_le": tag_le,
                "tag_be": tag_be,
                "function_count": len(funcs),
                "total_hits": tag_to_hits[tag_le],
                "sample_functions": ";".join(
                    sorted(f"{ep}:{name}" for ep, name in list(funcs)[:12])
                ),
            }
        )
    summary_rows.sort(
        key=lambda r: (-int(r["function_count"]), -int(r["total_hits"]), r["tag_le"])
    )

    detail_csv.parent.mkdir(parents=True, exist_ok=True)
    with detail_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "tag_le",
                "tag_be",
                "value_hex",
                "function_addr",
                "function_name",
                "hit_count",
                "sample_insn_addrs",
            ],
        )
        w.writeheader()
        for row in detail_rows:
            out = dict(row)
            out["sample_insn_addrs"] = ";".join(row["sample_insn_addrs"])
            w.writerow(out)

    with summary_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["tag_le", "tag_be", "function_count", "total_hits", "sample_functions"],
        )
        w.writeheader()
        w.writerows(summary_rows)

    print(f"[saved] detail={detail_csv} rows={len(detail_rows)}")
    print(f"[saved] summary={summary_csv} rows={len(summary_rows)}")
    print(
        "[mode] only_unresolved="
        f"{args.only_unresolved} name_regex={args.name_regex if args.name_regex else '<none>'}"
    )
    for row in summary_rows[:80]:
        print(
            f"{row['tag_le']} ({row['tag_be']}),funcs={row['function_count']},hits={row['total_hits']},"
            f"samples={row['sample_functions']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
