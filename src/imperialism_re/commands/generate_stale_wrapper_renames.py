#!/usr/bin/env python3
"""
Generate rename CSV for stale WrapperFor_*_At<addr> function names.

A wrapper name becomes stale when the function it wraps has been renamed
but the wrapper's own name still refers to the old target name.

Detection:
  - Source name matches WrapperFor_<embeddedName>_At<8hex>
  - The function body is a single JMP or a CALL+RET
  - The JMP/CALL target's current name differs from <embeddedName>
  - Double-nesting guard: skip if new name would produce WrapperFor_WrapperFor_

Output CSV columns (apply_fid_candidates-compatible):
  address, new_name, raw_match_name, source

Usage:
  uv run impk generate_stale_wrapper_renames \\
      --out-csv tmp_decomp/stale_wrapper_renames.csv
  uv run impk apply_fid_candidates \\
      --in-csv tmp_decomp/stale_wrapper_renames.csv \\
      --override-conflicts --apply
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex

_WRAPPER_RE = re.compile(r"^WrapperFor_(.+)_At([0-9a-fA-F]{8})$")

_GENERIC_PREFIXES = (
    "FUN_", "thunk_FUN_", "Cluster_", "DAT_", "PTR_",
    "OrphanVtableAssignStub_", "OrphanRetStub_",
)


def _is_generic(name: str) -> bool:
    for p in _GENERIC_PREFIXES:
        if name.startswith(p):
            return True
    return False


def _detect_single_forward_target(fn, fm, listing):
    """Return the single JMP or CALL+RET forward target, or None."""
    body = fn.getBody()
    if body is None:
        return None
    ins_iter = listing.getInstructions(body, True)
    ins = []
    while ins_iter.hasNext():
        ins.append(ins_iter.next())
        if len(ins) > 3:
            break

    if not ins:
        return None

    mnemonic0 = str(ins[0].getMnemonicString()).upper()

    if len(ins) == 1 and mnemonic0 == "JMP":
        flows = ins[0].getFlows()
        if flows and len(flows) == 1:
            tgt = fm.getFunctionAt(flows[0])
            if tgt is not None and not tgt.getEntryPoint().isExternalAddress():
                return tgt

    if len(ins) == 2 and mnemonic0 == "CALL":
        if str(ins[1].getMnemonicString()).upper() == "RET":
            refs = ins[0].getReferencesFrom()
            for ref in refs:
                callee = fm.getFunctionAt(ref.getToAddress())
                if callee is not None and not callee.getEntryPoint().isExternalAddress():
                    return callee

    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate renames for stale WrapperFor_*_At<addr> names."
    )
    ap.add_argument("--out-csv", required=True, help="Output CSV path")
    ap.add_argument("--start", default="0x00400000", help="Start address (inclusive)")
    ap.add_argument("--end", default="0x00700000", help="End address (exclusive)")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    root = resolve_project_root(args.project_root)
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []

    with open_program(root) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ep = int(str(fn.getEntryPoint()), 16)
            if ep < start or ep >= end:
                continue

            name = fn.getName()
            m = _WRAPPER_RE.match(name)
            if not m:
                continue
            embedded_name = m.group(1)
            # embedded_addr may be self-addr or target-addr — check both
            embedded_addr = int(m.group(2), 16)

            # backtick / mangled names are not stale candidates
            if "`" in name or "@@" in name:
                continue

            tgt = _detect_single_forward_target(fn, fm, listing)
            if tgt is None:
                continue
            tgt_name = tgt.getName()
            if _is_generic(tgt_name):
                continue

            # Not stale if already matching
            if embedded_name == tgt_name:
                continue

            # Double-nesting guard: skip if new name would be WrapperFor_WrapperFor_
            if tgt_name.startswith("WrapperFor_"):
                continue

            new_name = f"WrapperFor_{tgt_name}_At{ep:08x}"
            rows.append(
                {
                    "address": f"0x{ep:08x}",
                    "new_name": new_name,
                    "raw_match_name": name,
                    "source": "stale_wrapper",
                }
            )

    rows.sort(key=lambda r: int(r["address"], 16))

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["address", "new_name", "raw_match_name", "source"]
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[saved] {out_csv}  rows={len(rows)}")
    for r in rows:
        print(f"  {r['address']}  {r['raw_match_name']}")
        print(f"    -> {r['new_name']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
