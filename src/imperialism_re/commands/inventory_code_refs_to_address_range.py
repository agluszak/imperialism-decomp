#!/usr/bin/env python3
"""
Inventory code references/immediates that point into an address range.

This catches:
1) explicit Ghidra references from instructions (refs-from),
2) raw scalar immediates in instruction operands.

Usage:
  uv run impk inventory_code_refs_to_address_range \
    --addr-min 0x0066d9f0 --addr-max 0x0066da18 \
    --out-csv tmp_decomp/range_refs.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def in_range(v: int, lo: int, hi: int) -> bool:
    return lo <= v <= hi

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr-min", required=True)
    ap.add_argument("--addr-max", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    lo = parse_hex(args.addr_min)
    hi = parse_hex(args.addr_max)
    if hi < lo:
        lo, hi = hi, lo

    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []
    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        ins_it = listing.getInstructions(True)
        while ins_it.hasNext():
            ins = ins_it.next()
            addr = ins.getAddress()
            owner = fm.getFunctionContaining(addr)
            owner_addr = str(owner.getEntryPoint()) if owner is not None else "<no_func_addr>"
            owner_name = owner.getName() if owner is not None else "<no_func>"
            ins_text = str(ins)

            # 1) refs-from
            refs = ins.getReferencesFrom()
            for r in refs:
                to_addr = r.getToAddress()
                if to_addr is None:
                    continue
                to_off = to_addr.getOffset() & 0xFFFFFFFF
                if not in_range(to_off, lo, hi):
                    continue
                rows.append(
                    {
                        "from_addr": f"0x{addr.getOffset() & 0xFFFFFFFF:08x}",
                        "owner_addr": owner_addr,
                        "owner_name": owner_name,
                        "hit_kind": "ref",
                        "target_addr": f"0x{to_off:08x}",
                        "ref_type": str(r.getReferenceType()),
                        "instruction": ins_text,
                    }
                )

            # 2) operand scalar scan
            n_ops = ins.getNumOperands()
            for op_idx in range(n_ops):
                vals = ins.getOpObjects(op_idx)
                if vals is None:
                    continue
                for v in vals:
                    try:
                        sval = int(v.getValue()) & 0xFFFFFFFF
                    except Exception:
                        continue
                    if not in_range(sval, lo, hi):
                        continue
                    rows.append(
                        {
                            "from_addr": f"0x{addr.getOffset() & 0xFFFFFFFF:08x}",
                            "owner_addr": owner_addr,
                            "owner_name": owner_name,
                            "hit_kind": "scalar",
                            "target_addr": f"0x{sval:08x}",
                            "ref_type": "",
                            "instruction": ins_text,
                        }
                    )

    # de-dup
    uniq = {}
    for r in rows:
        key = (
            r["from_addr"],
            r["owner_addr"],
            r["owner_name"],
            r["hit_kind"],
            r["target_addr"],
            r["ref_type"],
            r["instruction"],
        )
        uniq[key] = r
    rows = sorted(
        uniq.values(),
        key=lambda r: (r["owner_name"], r["from_addr"], r["hit_kind"], r["target_addr"]),
    )

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "from_addr",
                "owner_addr",
                "owner_name",
                "hit_kind",
                "target_addr",
                "ref_type",
                "instruction",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[done] out={out_csv} rows={len(rows)} range=0x{lo:08x}..0x{hi:08x}")
    for r in rows[:200]:
        print(
            f"{r['from_addr']},{r['owner_name']},{r['hit_kind']},"
            f"{r['target_addr']},{r['ref_type']},\"{r['instruction']}\""
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
