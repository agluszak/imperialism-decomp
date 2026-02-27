#!/usr/bin/env python3
"""
Filter FID-derived rename candidates against current imperialism-decomp symbols.

Input CSV columns:
  address,new_name,raw_match_name,source

Outputs:
  1) thunk apply CSV: address,new_name,comment
  2) fun apply CSV:   address,new_name,comment
  3) report text

Usage:
  .venv/bin/python new_scripts/filter_fid_candidates_against_project.py \
    tmp_decomp/batch327_fid_single_match_candidates.csv \
    tmp_decomp/batch328_fid_thunk_apply.csv \
    tmp_decomp/batch328_fid_fun_apply.csv \
    tmp_decomp/batch328_fid_filter_report.txt
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


STRICT_PREFIX_ALLOW = (
    "Afx",
    "_Afx",
    "__",
    "_str",
    "_mem",
    "_wc",
    "_mb",
    "_abort",
)

STRICT_EXACT_ALLOW = {
    "__fpmath",
    "__ftol",
    "__allmul",
    "__allshl",
    "__aullshr",
    "__aullrem",
    "__aulldiv",
    "__global_unwind2",
    "__local_unwind2",
    "__abnormal_termination",
    "__NLG_Notify1",
    "__CallSettingFrame@12",
}

VERB_PREFIX_BLOCK = (
    "On",
    "Get",
    "Set",
    "Create",
    "Delete",
    "Read",
    "Write",
    "Add",
    "Remove",
    "Find",
    "Lookup",
    "Update",
    "Do",
    "Run",
    "Open",
    "Close",
    "Load",
    "Save",
    "Draw",
    "Enable",
    "Show",
    "Hide",
    "Move",
    "Select",
    "Insert",
    "Modify",
    "Track",
    "Scroll",
    "Center",
    "Parse",
    "Process",
    "Dispatch",
    "Map",
    "Handle",
    "Check",
    "Can",
    "Is",
    "Send",
    "Restore",
    "Copy",
    "Fill",
)


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def is_strong_name(raw: str) -> bool:
    if not raw:
        return False
    if raw in STRICT_EXACT_ALLOW:
        return True
    if raw.startswith(STRICT_PREFIX_ALLOW):
        return True
    if any(raw.startswith(v) for v in VERB_PREFIX_BLOCK):
        return False
    if raw.startswith("C"):
        return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", raw) is None:
        return False
    if len(raw) < 6:
        return False
    return False


def to_identifier(raw: str) -> str:
    raw = raw.strip().strip("`")
    raw = raw.replace("::", "_")
    raw = re.sub(r"[^0-9A-Za-z_]", "_", raw)
    raw = re.sub(r"_+", "_", raw).strip("_")
    if not raw:
        return ""
    if raw[0].isdigit():
        raw = "Lib_" + raw
    return raw


def write_apply_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: filter_fid_candidates_against_project.py "
            "<in_csv> <out_thunk_csv> <out_fun_csv> <out_report_txt>",
            file=sys.stderr,
        )
        return 2

    in_csv = Path(sys.argv[1])
    out_thunk_csv = Path(sys.argv[2])
    out_fun_csv = Path(sys.argv[3])
    out_report = Path(sys.argv[4])
    root = Path(__file__).resolve().parents[1]

    if not in_csv.exists():
        print(f"missing input: {in_csv}", file=sys.stderr)
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        write_apply_csv(out_thunk_csv, [])
        write_apply_csv(out_fun_csv, [])
        out_report.write_text("no input rows\n", encoding="utf-8")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    stats = {
        "input_rows": len(rows),
        "missing_function": 0,
        "already_named": 0,
        "thunk_kept": 0,
        "fun_kept": 0,
        "weak_name_rejected": 0,
    }
    thunk_rows: list[dict[str, str]] = []
    fun_rows: list[dict[str, str]] = []
    used_names: set[str] = set()

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()

        for row in rows:
            addr_txt = (row.get("address") or "").strip()
            raw_name = (row.get("raw_match_name") or "").strip()
            if not addr_txt:
                continue
            try:
                addr_int = parse_hex(addr_txt)
            except Exception:
                continue
            addr = af.getAddress(f"0x{addr_int:08x}")
            func = fm.getFunctionAt(addr)
            if func is None:
                stats["missing_function"] += 1
                continue

            cur = func.getName()
            if not (cur.startswith("FUN_") or cur.startswith("thunk_FUN_")):
                stats["already_named"] += 1
                continue

            if not is_strong_name(raw_name):
                stats["weak_name_rejected"] += 1
                continue

            base_name = to_identifier(raw_name)
            if not base_name:
                stats["weak_name_rejected"] += 1
                continue
            new_name = base_name
            if new_name in used_names:
                new_name = f"{base_name}_{addr_int:08x}"
            used_names.add(new_name)

            out_row = {
                "address": f"0x{addr_int:08x}",
                "new_name": new_name,
                "comment": f"[FID] Single Match: {raw_name}",
            }
            if cur.startswith("thunk_FUN_"):
                thunk_rows.append(out_row)
                stats["thunk_kept"] += 1
            else:
                fun_rows.append(out_row)
                stats["fun_kept"] += 1

    write_apply_csv(out_thunk_csv, thunk_rows)
    write_apply_csv(out_fun_csv, fun_rows)

    lines = [
        f"input_rows={stats['input_rows']}",
        f"missing_function={stats['missing_function']}",
        f"already_named={stats['already_named']}",
        f"weak_name_rejected={stats['weak_name_rejected']}",
        f"thunk_kept={stats['thunk_kept']}",
        f"fun_kept={stats['fun_kept']}",
        f"thunk_csv={out_thunk_csv}",
        f"fun_csv={out_fun_csv}",
    ]
    out_report.parent.mkdir(parents=True, exist_ok=True)
    out_report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
