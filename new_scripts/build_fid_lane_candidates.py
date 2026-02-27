#!/usr/bin/env python3
"""
Build rename candidates from FID bookmark CSV for a specific address lane.

Filters:
  - address in [start, end)
  - bookmark_comment contains "Single Match, <name>"
  - name passes include/exclude regex
  - current function at address is unresolved (FUN_* / thunk_FUN_*)

Output CSV columns:
  address,new_name,comment,raw_match_name,current_name

Usage:
  .venv/bin/python new_scripts/build_fid_lane_candidates.py \
    --bookmarks-csv tmp_decomp/batch352_mainproject_fid_bookmarks_refresh.csv \
    --start 0x00610000 --end 0x0061f000 \
    --include-regex \"Save|Load|Frame|Document|RecalcLayout|NegotiateBorderSpace\" \
    --out-csv tmp_decomp/batch360_fid_lane_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

RX_SINGLE = re.compile(r"Single Match,\s*(.*)$")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def to_identifier(raw: str) -> str:
    s = raw.strip().strip("`")
    s = s.replace("::", "_")
    s = re.sub(r"[^0-9A-Za-z_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return ""
    if s[0].isdigit():
        s = "Lib_" + s
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bookmarks-csv", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--include-regex", default=".*")
    ap.add_argument(
        "--exclude-regex",
        default=r"FID_conflict|scalar_deleting_destructor|vector_deleting_destructor|^operator$|^CPen$|^CBrush$|^Abort$",
    )
    ap.add_argument("--out-csv", required=True)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    bookmarks_csv = Path(args.bookmarks_csv)
    if not bookmarks_csv.is_absolute():
        bookmarks_csv = Path(args.project_root).resolve() / bookmarks_csv
    if not bookmarks_csv.exists():
        print(f"[error] missing bookmarks csv: {bookmarks_csv}")
        return 1

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = Path(args.project_root).resolve() / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    inc = re.compile(args.include_regex, re.IGNORECASE)
    exc = re.compile(args.exclude_regex, re.IGNORECASE) if args.exclude_regex else None

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    in_rows = list(csv.DictReader(bookmarks_csv.open("r", encoding="utf-8")))
    out_rows = []
    used_names: set[str] = set()

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        for r in in_rows:
            a_txt = (r.get("address") or "").strip()
            if not a_txt:
                continue
            try:
                addr_int = int(a_txt, 16)
            except Exception:
                continue
            if not (start <= addr_int < end):
                continue
            cmt = (r.get("bookmark_comment") or "").strip()
            m = RX_SINGLE.search(cmt)
            if not m:
                continue
            raw = m.group(1).strip()
            if not inc.search(raw):
                continue
            if exc is not None and exc.search(raw):
                continue

            addr = af.getAddress(f"0x{addr_int:08x}")
            f = fm.getFunctionAt(addr)
            if f is None:
                continue
            cur = f.getName()
            if not (cur.startswith("FUN_") or cur.startswith("thunk_FUN_")):
                continue

            new_name = to_identifier(raw)
            if not new_name:
                continue
            if new_name in used_names:
                new_name = f"{new_name}_{addr_int:08x}"
            used_names.add(new_name)

            out_rows.append(
                {
                    "address": f"0x{addr_int:08x}",
                    "new_name": new_name,
                    "comment": f"[FID-Lane] Single Match: {raw}",
                    "raw_match_name": raw,
                    "current_name": cur,
                }
            )

    out_rows.sort(key=lambda x: x["address"])
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["address", "new_name", "comment", "raw_match_name", "current_name"],
        )
        w.writeheader()
        w.writerows(out_rows)

    print(
        f"[done] in_rows={len(in_rows)} out_rows={len(out_rows)} "
        f"range=0x{start:08x}-0x{end:08x} -> {out_csv}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

