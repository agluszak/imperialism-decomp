#!/usr/bin/env python3
"""
Extend turn-instruction bindings with missing commands by inferring arity from
handler cursor increments in decompiled code.

This is intended for commands present in dispatch token maps but absent from
tabsenu TABLE_S* (e.g. pric/prov/tbar/tclr/coun).

Inputs:
  - Base bindings CSV (from build_tabsenu_schema_loader_bindings.py)
  - Dispatch token map CSV (batch55 map)

Output:
  - Extended bindings CSV with added rows where is_bound=1 and inferred arity.

Usage:
  .venv/bin/python new_scripts/extend_turn_instruction_bindings_from_handler_cursor.py \
    --base-bindings-csv tmp_decomp/batch419_tabsenu_loader_bindings.csv \
    --token-map-csv tmp_decomp/scenario_dispatch_token_handler_map_batch55.csv \
    --commands pric,prov,tbar,tclr,coun \
    --out-csv tmp_decomp/batch421_tabsenu_loader_bindings_extended.csv
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


def infer_arity_from_decomp(c_text: str) -> tuple[int, str]:
    # First pass: recover pointer vars that are loaded from stream cursor.
    pointer_vars = set(
        re.findall(
            r"\b([A-Za-z_]\w*)\s*=\s*\([^)]*\*\)\s*\*[A-Za-z_]\w*",
            c_text,
        )
    )

    best = 0
    confidence = "low"

    # High-confidence: explicit pointer increments/indexes on stream pointer vars.
    for pv in pointer_vars:
        plus_hits = [int(x) for x in re.findall(rf"\b{re.escape(pv)}\s*\+\s*(\d+)\b", c_text)]
        idx_hits = [int(x) + 1 for x in re.findall(rf"\b{re.escape(pv)}\[(\d+)\]", c_text)]
        cand = 0
        if plus_hits:
            cand = max(cand, max(plus_hits))
        if idx_hits:
            cand = max(cand, max(idx_hits))
        if cand > best:
            best = cand
            confidence = "high"

    if best > 0:
        return best, confidence

    # Medium-confidence fallback: generic pointer-index style.
    plus_hits = [int(x) for x in re.findall(r"\b[A-Za-z_]\w*\s*\+\s*(\d+)\b", c_text)]
    idx_hits = [int(x) + 1 for x in re.findall(r"\b[A-Za-z_]\w*\[(\d+)\]", c_text)]
    small = [x for x in plus_hits + idx_hits if 0 < x <= 16]
    if small:
        return max(small), "medium"

    return 0, "none"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base-bindings-csv",
        default="tmp_decomp/batch419_tabsenu_loader_bindings.csv",
        help="Base bindings CSV",
    )
    ap.add_argument(
        "--token-map-csv",
        default="tmp_decomp/scenario_dispatch_token_handler_map_batch55.csv",
        help="Dispatch token map CSV",
    )
    ap.add_argument(
        "--commands",
        default="pric,prov,tbar,tclr,coun",
        help="Comma-separated command list to force-extend",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/batch421_tabsenu_loader_bindings_extended.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    base_csv = Path(args.base_bindings_csv)
    if not base_csv.is_absolute():
        base_csv = root / base_csv
    token_csv = Path(args.token_map_csv)
    if not token_csv.is_absolute():
        token_csv = root / token_csv
    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv

    if not base_csv.exists():
        print(f"[error] missing base bindings: {base_csv}")
        return 1
    if not token_csv.exists():
        print(f"[error] missing token map: {token_csv}")
        return 1

    base_rows = list(csv.DictReader(base_csv.open("r", encoding="utf-8", newline="")))
    token_rows = list(csv.DictReader(token_csv.open("r", encoding="utf-8", newline="")))
    token_map = {}
    for r in token_rows:
        cmd = ((r.get("token_decoded") or r.get("token") or "")).strip().lower()
        if cmd:
            token_map[cmd] = r

    bound_cmds = {
        (r.get("command") or "").strip().lower()
        for r in base_rows
        if (r.get("is_bound") or "").strip() == "1"
    }
    wanted = [c.strip().lower() for c in args.commands.split(",") if c.strip()]
    missing = [c for c in wanted if c not in bound_cmds]
    print(f"[plan] base_rows={len(base_rows)} bound={len(bound_cmds)} requested={len(wanted)} missing={len(missing)}")

    if not missing:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", encoding="utf-8", newline="") as fh:
            wr = csv.DictWriter(fh, fieldnames=base_rows[0].keys() if base_rows else [])
            wr.writeheader()
            wr.writerows(base_rows)
        print(f"[done] no missing commands; copied base -> {out_csv}")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    added_rows: list[dict[str, str]] = []
    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        ifc = DecompInterface()
        ifc.openProgram(program)

        for cmd in missing:
            tr = token_map.get(cmd)
            if tr is None:
                print(f"[skip] {cmd}: missing in token map")
                continue
            target_va = (tr.get("target_va") or tr.get("target_addr") or "").strip()
            if not target_va:
                print(f"[skip] {cmd}: no target_va")
                continue
            addr = af.getAddress(f"0x{parse_hex(target_va):08x}")
            fn = fm.getFunctionAt(addr)
            if fn is None:
                print(f"[skip] {cmd}: no function at {target_va}")
                continue
            res = ifc.decompileFunction(fn, 45, None)
            if not res.decompileCompleted():
                print(f"[skip] {cmd}: decompile failed at {target_va}")
                continue
            c_text = str(res.getDecompiledFunction().getC())
            arity, confidence = infer_arity_from_decomp(c_text)
            if arity <= 0:
                print(f"[skip] {cmd}: could not infer arity")
                continue

            row = {
                "command": cmd,
                "token_raw": (tr.get("token_raw") or tr.get("token") or "").strip(),
                "dispatch_index": (tr.get("index") or "").strip(),
                "stub_va": (tr.get("stub_va") or tr.get("stub_addr") or "").strip(),
                "stub_name": (tr.get("stub_name") or "").strip(),
                "target_va": target_va,
                "target_name": (tr.get("target_name") or "").strip(),
                "arity_primary_loose": str(arity),
                "record_size_guess_loose": str(4 + (arity * 4)),
                "arity_primary_strict": str(arity),
                "record_size_guess_strict": str(4 + (arity * 4)),
                "strict_arity_override": str(arity),
                "is_bound": "1",
            }
            added_rows.append(row)
            print(
                f"[add] cmd={cmd} target={target_va} arity={arity} "
                f"confidence={confidence} target_name={row['target_name']}"
            )

    all_rows = list(base_rows) + added_rows
    all_rows.sort(
        key=lambda r: (
            int((r.get("dispatch_index") or "9999").strip() or "9999"),
            (r.get("command") or "").strip(),
        )
    )

    fields = [
        "command",
        "token_raw",
        "dispatch_index",
        "stub_va",
        "stub_name",
        "target_va",
        "target_name",
        "arity_primary_loose",
        "record_size_guess_loose",
        "arity_primary_strict",
        "record_size_guess_strict",
        "strict_arity_override",
        "is_bound",
    ]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=fields)
        wr.writeheader()
        wr.writerows(all_rows)

    print(f"[done] added={len(added_rows)} total={len(all_rows)} out={out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

