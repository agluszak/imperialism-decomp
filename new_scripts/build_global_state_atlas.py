#!/usr/bin/env python3
"""
Build a global-state atlas from Ghidra symbols and cross-references.

Outputs:
  - CSV: one row per selected global symbol with xref/read/write stats
  - JSON: machine-readable summary and top-ranked globals

Usage:
  .venv/bin/python new_scripts/build_global_state_atlas.py \
    --out-csv tmp_decomp/batch373_global_state_atlas.csv \
    --out-json tmp_decomp/batch373_global_state_atlas.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
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


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def ref_kind_flags(ref_type) -> tuple[bool, bool]:
    s = str(ref_type).upper()
    is_read = False
    is_write = False
    try:
        is_read = bool(ref_type.isRead())
    except Exception:
        is_read = "READ" in s or "DATA" in s
    try:
        is_write = bool(ref_type.isWrite())
    except Exception:
        is_write = "WRITE" in s
    if not is_read and not is_write and "DATA" in s:
        is_read = True
    return is_read, is_write


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/global_state_atlas.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--out-json",
        default="tmp_decomp/global_state_atlas.json",
        help="Output JSON path",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--start",
        default="0x00690000",
        help="Start address filter (inclusive)",
    )
    ap.add_argument(
        "--end",
        default="0x006b0000",
        help="End address filter (exclusive)",
    )
    ap.add_argument(
        "--name-regex",
        default=r"^(g_|DAT_006a|_DAT_006a|PTR_006a)",
        help="Regex filter for symbol names",
    )
    ap.add_argument(
        "--min-xrefs",
        type=int,
        default=4,
        help="Minimum total xrefs required",
    )
    ap.add_argument(
        "--top-k",
        type=int,
        default=120,
        help="Top rows to keep (by xref density)",
    )
    args = ap.parse_args()

    out_csv = Path(args.out_csv).resolve()
    out_json = Path(args.out_json).resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    root = Path(args.project_root).resolve()
    start_i = parse_hex(args.start)
    end_i = parse_hex(args.end)
    name_re = re.compile(args.name_regex)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        st = program.getSymbolTable()
        refm = program.getReferenceManager()
        fm = program.getFunctionManager()
        listing = program.getListing()

        it = st.getAllSymbols(True)
        while it.hasNext():
            sym = it.next()
            name = sym.getName()
            if not name_re.search(name):
                continue
            addr = sym.getAddress()
            if addr is None:
                continue
            addr_i = int(str(addr), 16)
            if addr_i < start_i or addr_i >= end_i:
                continue

            refs = list(refm.getReferencesTo(addr))
            if len(refs) < args.min_xrefs:
                continue

            read_refs = 0
            write_refs = 0
            code_refs = 0
            reader_hits: defaultdict[str, int] = defaultdict(int)
            writer_hits: defaultdict[str, int] = defaultdict(int)
            caller_hits: defaultdict[str, int] = defaultdict(int)

            for ref in refs:
                from_addr = ref.getFromAddress()
                if from_addr is None:
                    continue
                fn = fm.getFunctionContaining(from_addr)
                if fn is None:
                    continue
                code_refs += 1
                fn_name = fn.getName()
                caller_hits[fn_name] += 1
                is_read, is_write = ref_kind_flags(ref.getReferenceType())
                if is_read:
                    read_refs += 1
                    reader_hits[fn_name] += 1
                if is_write:
                    write_refs += 1
                    writer_hits[fn_name] += 1

            if code_refs < args.min_xrefs:
                continue

            data = listing.getDataAt(addr)
            dtype = str(data.getDataType()) if data is not None else ""
            dlen = str(data.getLength()) if data is not None else ""

            top_readers = sorted(reader_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
            top_writers = sorted(writer_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
            top_callers = sorted(caller_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:8]

            rows.append(
                {
                    "address": f"0x{addr_i:08x}",
                    "name": name,
                    "symbol_type": str(sym.getSymbolType()),
                    "data_type": dtype,
                    "data_len": dlen,
                    "xref_total": str(len(refs)),
                    "code_refs": str(code_refs),
                    "read_refs": str(read_refs),
                    "write_refs": str(write_refs),
                    "unique_reader_functions": str(len(reader_hits)),
                    "unique_writer_functions": str(len(writer_hits)),
                    "top_readers": ";".join(f"{n}:{c}" for n, c in top_readers),
                    "top_writers": ";".join(f"{n}:{c}" for n, c in top_writers),
                    "top_callers": ";".join(f"{n}:{c}" for n, c in top_callers),
                }
            )

    rows.sort(
        key=lambda r: (
            -int(r["code_refs"]),
            -int(r["write_refs"]),
            -int(r["unique_reader_functions"]),
            r["address"],
        )
    )
    if args.top_k > 0:
        rows = rows[: args.top_k]

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "address",
                "name",
                "symbol_type",
                "data_type",
                "data_len",
                "xref_total",
                "code_refs",
                "read_refs",
                "write_refs",
                "unique_reader_functions",
                "unique_writer_functions",
                "top_readers",
                "top_writers",
                "top_callers",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    summary = {
        "scope": {
            "start": f"0x{start_i:08x}",
            "end": f"0x{end_i:08x}",
            "name_regex": args.name_regex,
            "min_xrefs": args.min_xrefs,
            "top_k": args.top_k,
        },
        "rows": len(rows),
        "top_by_writes": [
            {
                "address": r["address"],
                "name": r["name"],
                "write_refs": int(r["write_refs"]),
                "top_writers": r["top_writers"],
            }
            for r in sorted(rows, key=lambda x: -int(x["write_refs"]))[:30]
        ],
        "top_by_reads": [
            {
                "address": r["address"],
                "name": r["name"],
                "read_refs": int(r["read_refs"]),
                "top_readers": r["top_readers"],
            }
            for r in sorted(rows, key=lambda x: -int(x["read_refs"]))[:30]
        ],
        "outputs": {
            "csv": str(out_csv),
            "json": str(out_json),
        },
    }
    out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[saved] {out_csv} rows={len(rows)}")
    print(f"[saved] {out_json}")
    for r in summary["top_by_writes"][:12]:
        print(
            f"[write-hot] {r['address']} {r['name']} "
            f"write_refs={r['write_refs']} writers={r['top_writers']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

