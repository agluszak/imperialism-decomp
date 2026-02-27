#!/usr/bin/env python3
"""
Build state-machine transition candidates from angr-discovered code-pointer tables.

Input:
  CSV from angr_scan_codeptr_tables.py with columns:
    table_va, section, run_len, first_ptr, last_ptr

Output:
  - CSV transition candidates (source function -> target handler via table)
  - JSON summary by table

Usage:
  .venv/bin/python new_scripts/build_transition_candidates_from_tables.py \
      <tables_csv> <out_csv> <out_json> [project_root]
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

FLOW_KEYWORDS = re.compile(
    r"(tactical|battle|army|navy|turn|event|instruction|maporder|mapaction|civilian|dispatch)",
    re.IGNORECASE,
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


def subsystem_hint(source_name: str, target_name: str) -> str:
    txt = f"{source_name} {target_name}".lower()
    if any(k in txt for k in ("tactical", "battle", "army", "navy")):
        return "TACTICAL"
    if any(k in txt for k in ("turn", "event", "instruction")):
        return "TURN"
    if any(k in txt for k in ("maporder", "mapaction", "civilian")):
        return "MAP_ORDER"
    return "UNKNOWN"


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "usage: .venv/bin/python new_scripts/build_transition_candidates_from_tables.py "
            "<tables_csv> <out_csv> <out_json> [project_root]"
        )
        return 1

    tables_csv = Path(sys.argv[1]).resolve()
    out_csv = Path(sys.argv[2]).resolve()
    out_json = Path(sys.argv[3]).resolve()
    root = (
        Path(sys.argv[4]).resolve()
        if len(sys.argv) >= 5
        else Path(__file__).resolve().parents[1]
    )

    if not tables_csv.exists():
        print(f"missing input csv: {tables_csv}")
        return 1

    table_rows = list(csv.DictReader(tables_csv.open("r", encoding="utf-8", newline="")))
    if not table_rows:
        print("no table rows in input")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    transitions: list[dict[str, str]] = []
    table_summary: dict[str, dict] = {}
    subsys_counter: Counter[str] = Counter()

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        refm = program.getReferenceManager()
        mem = program.getMemory()

        for row in table_rows:
            try:
                table_addr_int = parse_hex(row["table_va"])
                run_len = int((row.get("run_len") or "0").strip())
            except Exception:
                continue
            if run_len <= 0:
                continue

            table_addr = af.getAddress(f"0x{table_addr_int:08x}")
            if table_addr is None:
                continue

            targets: list[tuple[int, str]] = []
            for idx in range(run_len):
                ea = table_addr.add(idx * 4)
                try:
                    ptr = mem.getInt(ea) & 0xFFFFFFFF
                except Exception:
                    continue
                taddr = af.getAddress(f"0x{ptr:08x}")
                tfunc = fm.getFunctionAt(taddr)
                if tfunc is None:
                    tfunc = fm.getFunctionContaining(taddr)
                if tfunc is None:
                    continue
                targets.append((ptr, tfunc.getName()))

            if not targets:
                continue

            xrefs = list(refm.getReferencesTo(table_addr))
            source_sites: list[tuple[str, str, str]] = []
            for xr in xrefs:
                from_addr = xr.getFromAddress()
                sfunc = fm.getFunctionContaining(from_addr)
                if sfunc is None:
                    continue
                source_sites.append((str(from_addr), sfunc.getName(), str(xr.getReferenceType())))

            # If no source xrefs, keep table summary only.
            if not source_sites:
                table_summary[f"0x{table_addr_int:08x}"] = {
                    "table_va": f"0x{table_addr_int:08x}",
                    "run_len": run_len,
                    "targets_kept": len(targets),
                    "source_sites": 0,
                }
                continue

            local_rows = 0
            for src_site, src_name, xref_type in source_sites:
                for tgt_addr, tgt_name in targets:
                    if not FLOW_KEYWORDS.search(src_name) and not FLOW_KEYWORDS.search(tgt_name):
                        continue
                    hint = subsystem_hint(src_name, tgt_name)
                    subsys_counter[hint] += 1
                    transitions.append(
                        {
                            "table_va": f"0x{table_addr_int:08x}",
                            "source_site": src_site,
                            "source_func": src_name,
                            "target_addr": f"0x{tgt_addr:08x}",
                            "target_func": tgt_name,
                            "xref_type": xref_type,
                            "subsystem_hint": hint,
                            "evidence": "table_xref_plus_codeptr_entry",
                        }
                    )
                    local_rows += 1

            table_summary[f"0x{table_addr_int:08x}"] = {
                "table_va": f"0x{table_addr_int:08x}",
                "run_len": run_len,
                "targets_kept": len(targets),
                "source_sites": len(source_sites),
                "transitions_emitted": local_rows,
            }

    transitions.sort(
        key=lambda r: (
            r["subsystem_hint"],
            r["source_func"].lower(),
            r["target_func"].lower(),
            r["table_va"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "table_va",
                "source_site",
                "source_func",
                "target_addr",
                "target_func",
                "xref_type",
                "subsystem_hint",
                "evidence",
            ],
        )
        w.writeheader()
        w.writerows(transitions)

    table_items = list(table_summary.values())
    table_items.sort(key=lambda d: d.get("transitions_emitted", 0), reverse=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(
            {
                "input_tables_csv": str(tables_csv),
                "tables_scanned": len(table_rows),
                "tables_with_summary": len(table_items),
                "transition_rows": len(transitions),
                "subsystem_counts": dict(subsys_counter),
                "tables": table_items[:200],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"[saved] csv={out_csv} rows={len(transitions)}")
    print(f"[saved] json={out_json} tables={len(table_items)}")
    if subsys_counter:
        print("[subsystems]")
        for k, v in subsys_counter.most_common():
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
