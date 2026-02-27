#!/usr/bin/env python3
"""
Generate rename CSV for tiny CALL-wrapper generic functions with address fallback.

Selection gates:
  - function name matches regex (default: ^FUN_)
  - instruction count <= max-instructions
  - exactly one internal CALL target across whole body
  - body contains RET
  - no branch/jump mnemonics other than CALL/RET

Naming:
  - target named (non-generic): WrapperFor_<TargetName>_At<SrcAddr>
  - target generic:             WrapperFor_Target_<TargetAddr>_At<SrcAddr>

Output CSV columns:
  address,new_name,comment,old_name,target_name,target_addr,target_is_generic,instruction_count
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


def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "UnknownTarget"
    if s[0].isdigit():
        s = "_" + s
    return s


def is_generic(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x00400000")
    ap.add_argument("--end", default="0x00700000")
    ap.add_argument("--name-regex", default=r"^FUN_")
    ap.add_argument("--max-instructions", type=int, default=8)
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/call_wrapper_addr_fallback_renames.csv",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    start = parse_hex(args.start)
    end = parse_hex(args.end)
    name_re = re.compile(args.name_regex)
    out_csv = Path(args.out_csv).resolve()
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        existing_names = set()
        fit = fm.getFunctions(True)
        funcs = []
        while fit.hasNext():
            f = fit.next()
            funcs.append(f)
            existing_names.add(f.getName())
        used_names = set(existing_names)

        for f in funcs:
            src_addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            if src_addr < start or src_addr >= end:
                continue
            old_name = f.getName()
            if not name_re.search(old_name):
                continue

            insns = []
            it = listing.getInstructions(f.getBody(), True)
            while it.hasNext():
                insns.append(it.next())
                if len(insns) > args.max_instructions:
                    break
            if len(insns) == 0 or len(insns) > args.max_instructions:
                continue

            has_ret = False
            call_targets: set[int] = set()
            blocked = False

            for ins in insns:
                m = str(ins.getMnemonicString()).upper()
                if m == "RET":
                    has_ret = True
                    continue
                if m == "CALL":
                    refs = ins.getReferencesFrom()
                    for ref in refs:
                        callee = fm.getFunctionAt(ref.getToAddress())
                        if callee is None:
                            continue
                        ep_txt = str(callee.getEntryPoint())
                        if ep_txt.startswith("EXTERNAL:"):
                            continue
                        call_targets.add(callee.getEntryPoint().getOffset() & 0xFFFFFFFF)
                    continue
                # Reject jumps/branches for this wrapper lane.
                if m.startswith("J"):
                    blocked = True
                    break

            if blocked or not has_ret:
                continue
            if len(call_targets) != 1:
                continue

            target_addr = next(iter(call_targets))
            target = fm.getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(f"0x{target_addr:08x}"))
            if target is None:
                continue
            target_name = target.getName()
            target_generic = is_generic(target_name)

            if target_generic:
                base = f"WrapperFor_Target_{target_addr:08x}_At{src_addr:08x}"
            else:
                base = f"WrapperFor_{sanitize_symbol_name(target_name)}_At{src_addr:08x}"

            new_name = base
            i = 2
            while new_name in used_names:
                new_name = f"{base}_{i}"
                i += 1
            if new_name == old_name:
                continue
            used_names.add(new_name)

            rows.append(
                {
                    "address": f"0x{src_addr:08x}",
                    "new_name": new_name,
                    "comment": (
                        f"[CallWrapper] tiny wrapper around {target_name}@0x{target_addr:08x}"
                    ),
                    "old_name": old_name,
                    "target_name": target_name,
                    "target_addr": f"0x{target_addr:08x}",
                    "target_is_generic": "1" if target_generic else "0",
                    "instruction_count": str(len(insns)),
                }
            )

    rows.sort(key=lambda r: r["address"])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "new_name",
                "comment",
                "old_name",
                "target_name",
                "target_addr",
                "target_is_generic",
                "instruction_count",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    generic_targets = sum(1 for r in rows if r["target_is_generic"] == "1")
    print(
        f"[saved] {out_csv} rows={len(rows)} generic_target_rows={generic_targets} "
        f"range=0x{start:08x}-0x{end:08x} name_regex={args.name_regex} "
        f"max_instructions={args.max_instructions}"
    )
    for r in rows[:120]:
        print(
            f"{r['address']},{r['old_name']} -> {r['new_name']},"
            f"target={r['target_name']}@{r['target_addr']},ins={r['instruction_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
