#!/usr/bin/env python3
"""
Scan a PE binary for contiguous code-pointer tables using angr/CLE.

Usage:
  .venv/bin/python new_scripts/angr_scan_codeptr_tables.py <exe_path> [out_csv] [min_run]

Output columns:
  table_va, section, run_len, first_ptr, last_ptr
"""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path

import angr


def usage() -> int:
    print(
        "usage: .venv/bin/python new_scripts/angr_scan_codeptr_tables.py <exe_path> [out_csv] [min_run]"
    )
    return 1


def main() -> int:
    if len(sys.argv) < 2:
        return usage()

    exe_path = Path(sys.argv[1]).resolve()
    if not exe_path.exists():
        print(f"missing exe: {exe_path}")
        return 1

    out_csv = (
        Path(sys.argv[2]).resolve()
        if len(sys.argv) >= 3
        else Path("tmp_decomp/angr_codeptr_tables.csv").resolve()
    )
    min_run = int(sys.argv[3]) if len(sys.argv) >= 4 else 8

    proj = angr.Project(str(exe_path), load_options={"auto_load_libs": False})
    main_obj = proj.loader.main_object

    text_sec = main_obj.find_section_containing(main_obj.entry)
    if text_sec is None:
        print("could not locate .text section from entry")
        return 1

    text_min = text_sec.min_addr
    text_max = text_sec.max_addr

    target_secs = []
    for sec in main_obj.sections:
        name = sec.name or ""
        if name in (".data", ".rdata"):
            target_secs.append(sec)

    if not target_secs:
        print("no .data/.rdata sections found")
        return 1

    raw_exe = exe_path.read_bytes()
    rows: list[tuple[int, str, int, int, int]] = []

    for sec in target_secs:
        file_off = int(getattr(sec, "offset", 0))
        file_size = int(getattr(sec, "filesize", 0))
        if file_size <= 0:
            continue
        if file_off < 0 or file_off + file_size > len(raw_exe):
            continue
        sec_data = raw_exe[file_off : file_off + file_size]
        run_start = -1
        run_vals: list[int] = []

        for off in range(0, len(sec_data) - 3, 4):
            ptr = struct.unpack_from("<I", sec_data, off)[0]
            is_code_ptr = text_min <= ptr <= text_max
            if is_code_ptr:
                if run_start < 0:
                    run_start = off
                    run_vals = [ptr]
                else:
                    run_vals.append(ptr)
            else:
                if run_start >= 0 and len(run_vals) >= min_run:
                    table_va = sec.min_addr + run_start
                    rows.append((table_va, sec.name, len(run_vals), run_vals[0], run_vals[-1]))
                run_start = -1
                run_vals = []

        if run_start >= 0 and len(run_vals) >= min_run:
            table_va = sec.min_addr + run_start
            rows.append((table_va, sec.name, len(run_vals), run_vals[0], run_vals[-1]))

    rows.sort(key=lambda r: (r[0], -r[2]))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["table_va", "section", "run_len", "first_ptr", "last_ptr"])
        for table_va, sec_name, run_len, first_ptr, last_ptr in rows:
            w.writerow(
                [
                    f"0x{table_va:08x}",
                    sec_name,
                    run_len,
                    f"0x{first_ptr:08x}",
                    f"0x{last_ptr:08x}",
                ]
            )

    print(f"[saved] {out_csv} rows={len(rows)} min_run={min_run}")
    for table_va, sec_name, run_len, first_ptr, last_ptr in rows[:30]:
        print(
            f"0x{table_va:08x} {sec_name:7s} len={run_len:3d} first=0x{first_ptr:08x} last=0x{last_ptr:08x}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
