#!/usr/bin/env python3
"""
Enrich orphan triage rows into an intent inventory with reference evidence.

Input:
  CSV from triage_orphan_functions.py

Output:
  CSV with intent buckets and ref counts:
    address,name,classification,instruction_count,call_count,code_xrefs,
    total_refs,data_refs,orphan_intent,justification

Intent buckets:
  - intentional_thunk_entry
  - intentional_stub
  - intentional_wrapper
  - data_driven_entrypoint
  - detached_callchain_no_inrefs
  - dead_leaf_candidate
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def i(text: str | None) -> int:
    try:
        return int((text or "").strip() or "0")
    except Exception:
        return 0


def parse_addr(text: str) -> int:
    t = (text or "").strip().lower()
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


def classify_intent(
    name: str,
    klass: str,
    ins_count: int,
    call_count: int,
    preview: str,
    data_refs: int,
) -> tuple[str, str]:
    if name.startswith("OrphanDeadLeaf_"):
        return ("intentional_dead_leaf_named", "explicitly marked detached dead leaf")
    if name.startswith("thunk_") or (ins_count == 1 and preview.upper().startswith("JMP ")):
        return ("intentional_thunk_entry", "single-hop thunk island entry")
    if klass in {"ret_stub", "padding_stub", "vtable_assign_stub"}:
        return ("intentional_stub", f"classification={klass}")
    if name.startswith("WrapperFor_"):
        return ("intentional_wrapper", "named wrapper-style entry")
    if data_refs > 0:
        return ("data_driven_entrypoint", f"referenced by data/table refs={data_refs}")
    if call_count > 0:
        return ("detached_callchain_no_inrefs", f"contains calls={call_count} but no incoming code refs")
    return ("dead_leaf_candidate", "no incoming refs, no data refs, no internal calls")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="Input orphan triage csv")
    ap.add_argument("--out-csv", required=True, help="Output enriched inventory csv")
    ap.add_argument(
        "--out-summary",
        default="",
        help="Optional plain-text summary file",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_summary = Path(args.out_summary) if args.out_summary else None
    if out_summary is not None and not out_summary.is_absolute():
        out_summary = root / out_summary
    if out_summary is not None:
        out_summary.parent.mkdir(parents=True, exist_ok=True)

    if not in_csv.exists():
        print(f"[error] missing input csv: {in_csv}")
        return 1

    triage_rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    if not triage_rows:
        print("[error] input csv is empty")
        return 1

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    out_rows = []
    intent_counts = Counter()
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        for r in triage_rows:
            addr_txt = (r.get("address") or "").strip()
            try:
                addr_int = parse_addr(addr_txt)
            except Exception:
                continue
            addr = af.getAddress(f"0x{addr_int:08x}")

            total_refs = 0
            code_refs = 0
            data_refs = 0
            refs = rm.getReferencesTo(addr)
            for ref in refs:
                total_refs += 1
                from_addr = ref.getFromAddress()
                if from_addr is not None and fm.getFunctionContaining(from_addr) is not None:
                    code_refs += 1
                else:
                    data_refs += 1

            name = (r.get("name") or "").strip()
            klass = (r.get("classification") or "").strip()
            ins_count = i(r.get("instruction_count"))
            call_count = i(r.get("call_count"))
            preview = (r.get("instruction_preview") or "").strip()

            intent, why = classify_intent(
                name=name,
                klass=klass,
                ins_count=ins_count,
                call_count=call_count,
                preview=preview,
                data_refs=data_refs,
            )
            intent_counts[intent] += 1

            out_rows.append(
                {
                    "address": f"0x{addr_int:08x}",
                    "name": name,
                    "classification": klass,
                    "instruction_count": str(ins_count),
                    "call_count": str(call_count),
                    "code_xrefs": str(code_refs),
                    "total_refs": str(total_refs),
                    "data_refs": str(data_refs),
                    "orphan_intent": intent,
                    "justification": why,
                }
            )

    out_rows.sort(key=lambda x: (x["orphan_intent"], x["address"]))
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "name",
                "classification",
                "instruction_count",
                "call_count",
                "code_xrefs",
                "total_refs",
                "data_refs",
                "orphan_intent",
                "justification",
            ],
        )
        w.writeheader()
        w.writerows(out_rows)

    print(f"[saved] {out_csv} rows={len(out_rows)}")
    for key, val in sorted(intent_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"[intent] {key}={val}")

    if out_summary is not None:
        lines = [f"rows={len(out_rows)}"]
        for key, val in sorted(intent_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"{key}={val}")
        out_summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[saved] {out_summary}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
