#!/usr/bin/env python3
"""
Triage orphan functions (no incoming code refs) in an address range.

This is used to classify tiny/noise functions into safe buckets:
  - ret_stub
  - vtable_assign_stub
  - padding_stub
  - orphan_leaf_unknown

Usage:
  .venv/bin/python new_scripts/triage_orphan_functions.py \
    --addr-min 0x00600000 --addr-max 0x0062ffff \
    --out-csv tmp_decomp/orphan_triage_0060_0062.csv
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


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
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


def classify(instructions: list[str], code_xrefs: int, call_count: int) -> tuple[str, str]:
    if code_xrefs != 0:
        return ("not_orphan", "skip")
    if not instructions:
        return ("empty_or_data", "inspect_boundary")

    up = [s.upper() for s in instructions]
    mnems = [s.split()[0] if s else "" for s in up]

    if all(m in {"RET", "RETN", "RETNQ"} for m in mnems):
        return ("ret_stub", "rename_noop_or_slot_stub")

    if all(m in {"NOP", "INT3", "RET", "RETN", "RETNQ"} for m in mnems):
        return ("padding_stub", "consider_delete_and_recreate_boundary")

    if (
        len(up) <= 3
        and any(s.startswith("MOV ") and ",0X" in s for s in up)
        and any(m in {"RET", "RETN", "RETNQ"} for m in mnems)
    ):
        return ("vtable_assign_stub", "rename_vtable_initializer_stub")

    if call_count == 0:
        return ("orphan_leaf_unknown", "manual_context_review")
    return ("orphan_unknown_with_calls", "manual_context_review")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr-min", required=True)
    ap.add_argument("--addr-max", required=True)
    ap.add_argument("--name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--max-code-xrefs", type=int, default=0)
    ap.add_argument("--out-csv", default="tmp_decomp/orphan_triage.csv")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    name_re = re.compile(args.name_regex)
    root = Path(args.project_root).resolve()
    out_csv = Path(args.out_csv)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if addr < lo or addr > hi:
                continue
            name = f.getName()
            if not name_re.search(name):
                continue

            code_xrefs = 0
            for ref in rm.getReferencesTo(af.getAddress(f"0x{addr:08x}")):
                from_addr = ref.getFromAddress()
                if from_addr is None:
                    continue
                if fm.getFunctionContaining(from_addr) is not None:
                    code_xrefs += 1
            if code_xrefs > args.max_code_xrefs:
                continue

            ins_text: list[str] = []
            call_count = 0
            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                txt = str(ins)
                ins_text.append(txt)
                if str(ins.getMnemonicString()).upper() == "CALL":
                    call_count += 1

            klass, action = classify(ins_text, code_xrefs, call_count)
            preview = " | ".join(ins_text[:5])
            rows.append(
                {
                    "address": f"0x{addr:08x}",
                    "name": name,
                    "instruction_count": str(len(ins_text)),
                    "call_count": str(call_count),
                    "code_xrefs": str(code_xrefs),
                    "classification": klass,
                    "suggested_action": action,
                    "instruction_preview": preview,
                }
            )

    rows.sort(
        key=lambda r: (
            r["classification"],
            int(r["instruction_count"]),
            r["address"],
        )
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "name",
                "instruction_count",
                "call_count",
                "code_xrefs",
                "classification",
                "suggested_action",
                "instruction_preview",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    for r in rows[:120]:
        print(
            f"{r['address']},{r['name']},class={r['classification']},"
            f"ins={r['instruction_count']},calls={r['call_count']},xrefs={r['code_xrefs']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
