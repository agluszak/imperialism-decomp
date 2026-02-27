#!/usr/bin/env python3
"""
Generate create/rename rows for missing (or generic) single-JMP thunk entries
that jump to selected target functions.

Output CSV is compatible with create_specific_jmp_thunks_from_csv.py:
  source_addr,target_addr,new_name,target_name,comment

Usage:
  uv run impk generate_missing_jmp_thunks_for_targets \
    --targets-csv tmp_decomp/batch712_trade_residual_globals.csv \
    --out-csv tmp_decomp/batch712_trade_missing_jmp_thunks.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

def sanitize_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "target"
    if s[0].isdigit():
        s = "_" + s
    return s

def is_generic_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )

def load_targets_from_csv(path: Path) -> list[int]:
    rows = list(csv.DictReader(path.open("r", encoding="utf-8", newline="")))
    out: list[int] = []
    seen: set[int] = set()
    for r in rows:
        raw = (
            (r.get("address") or "").strip()
            or (r.get("target_addr") or "").strip()
            or (r.get("addr") or "").strip()
        )
        if not raw:
            continue
        try:
            a = parse_hex(raw)
        except Exception:
            continue
        if a in seen:
            continue
        seen.add(a)
        out.append(a)
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", nargs="*", default=[], help="Target function addresses")
    ap.add_argument("--targets-csv", default="", help="CSV with address/target_addr column")
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--source-start", default="", help="Optional source range start")
    ap.add_argument("--source-end", default="", help="Optional source range end (exclusive)")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    targets: list[int] = []
    seen: set[int] = set()

    for raw in args.targets:
        try:
            a = parse_hex(raw)
        except Exception:
            continue
        if a not in seen:
            seen.add(a)
            targets.append(a)

    if args.targets_csv:
        csv_path = Path(args.targets_csv)
        if not csv_path.is_absolute():
            csv_path = resolve_project_root(args.project_root) / csv_path
        if not csv_path.exists():
            print(f"[error] missing targets-csv: {csv_path}")
            return 1
        for a in load_targets_from_csv(csv_path):
            if a not in seen:
                seen.add(a)
                targets.append(a)

    if not targets:
        print("[error] no targets")
        return 1

    source_start = parse_hex(args.source_start) if args.source_start else None
    source_end = parse_hex(args.source_end) if args.source_end else None

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = resolve_project_root(args.project_root) / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    root = resolve_project_root(args.project_root)

    rows: list[dict[str, str]] = []
    seen_src_target: set[tuple[int, int]] = set()

    with open_program(root) as program:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()

        for targ in targets:
            t_addr = af.getAddress(f"0x{targ:08x}")
            t_func = fm.getFunctionAt(t_addr)
            if t_func is None:
                print(f"[warn] missing target function 0x{targ:08x}")
                continue
            target_name = t_func.getName()
            safe_target = sanitize_name(target_name)

            refs = rm.getReferencesTo(t_addr)
            while refs.hasNext():
                ref = refs.next()
                src_addr = ref.getFromAddress()
                src = int(src_addr.getOffset() & 0xFFFFFFFF)

                if source_start is not None and src < source_start:
                    continue
                if source_end is not None and src >= source_end:
                    continue

                ins = listing.getInstructionAt(src_addr)
                if ins is None:
                    continue
                if str(ins.getMnemonicString()).upper() != "JMP":
                    continue
                flows = ins.getFlows()
                if flows is None or len(flows) != 1:
                    continue
                if int(flows[0].getOffset() & 0xFFFFFFFF) != targ:
                    continue

                f_at_src = fm.getFunctionAt(src_addr)
                f_containing = fm.getFunctionContaining(src_addr)
                if f_containing is not None and f_at_src is None:
                    # Interior JMP inside an existing function body, not an entry thunk.
                    continue
                if f_at_src is not None and not is_generic_name(f_at_src.getName()):
                    # Already curated name at source; do not override.
                    continue

                key = (src, targ)
                if key in seen_src_target:
                    continue
                seen_src_target.add(key)

                new_name = f"thunk_{safe_target}_At{src:08x}"
                rows.append(
                    {
                        "source_addr": f"0x{src:08x}",
                        "target_addr": f"0x{targ:08x}",
                        "new_name": new_name,
                        "target_name": target_name,
                        "comment": f"Single-JMP thunk to {target_name}",
                    }
                )

    rows.sort(key=lambda r: (r["source_addr"], r["target_addr"]))
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["source_addr", "target_addr", "new_name", "target_name", "comment"],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv} rows={len(rows)} targets={len(targets)}")
    for r in rows[:200]:
        print(f"{r['source_addr']} -> {r['target_addr']} {r['new_name']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
