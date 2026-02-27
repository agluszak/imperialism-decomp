#!/usr/bin/env python3
"""
Infer canonical g_vtblT* labels from named constructor functions.

Heuristic:
1) Match constructor functions named `ConstructT*BaseState`.
2) Decompile and collect vtable literal assignments (`PTR_LAB_00xxxxxx`).
3) Use the last observed vtable literal as the most-derived constructor write.
4) Create `g_vtbl<TClass>` label when missing.

Safety:
- skip if target class already has canonical vtbl label anywhere.
- skip if target address already has conflicting canonical g_vtblT* label.

Usage:
  .venv/bin/python new_scripts/extract_vtbl_labels_from_named_ctors.py
  .venv/bin/python new_scripts/extract_vtbl_labels_from_named_ctors.py --apply
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

CTOR_RE = re.compile(r"^Construct(T[A-Za-z0-9_]+)BaseState$")
VTBL_RE = re.compile(r"PTR_LAB_00([0-9a-fA-F]{6})")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write labels")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()

        ifc = DecompInterface()
        ifc.openProgram(program)

        # Collect existing canonical vtbl names.
        existing_canonical_names = set()
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            n = sit.next().getName()
            if n.startswith("g_vtblT"):
                existing_canonical_names.add(n)

        candidates = []
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            m = CTOR_RE.match(f.getName())
            if not m:
                continue
            tname = m.group(1)
            label = f"g_vtbl{tname}"
            if label in existing_canonical_names:
                continue

            res = ifc.decompileFunction(f, 30, None)
            if not res.decompileCompleted():
                continue
            c_text = str(res.getDecompiledFunction().getC())
            hits = VTBL_RE.findall(c_text)
            if not hits:
                continue
            vtbl_addr = int("00" + hits[-1], 16)
            candidates.append(
                {
                    "tname": tname,
                    "ctor_addr": str(f.getEntryPoint()),
                    "ctor_name": f.getName(),
                    "vtbl_addr_int": vtbl_addr,
                    "vtbl_addr": f"0x{vtbl_addr:08x}",
                    "label": label,
                }
            )

        print(f"[candidates] {len(candidates)}")
        for c in candidates[:240]:
            print(
                f"{c['tname']},{c['ctor_addr']},{c['ctor_name']},"
                f"vtbl={c['vtbl_addr']},label={c['label']}"
            )
        if len(candidates) > 240:
            print(f"... ({len(candidates) - 240} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write labels")
            return 0

        tx = program.startTransaction("Extract vtbl labels from named ctors")
        ok = skip = fail = 0
        try:
            for c in candidates:
                addr = af.getAddress(c["vtbl_addr"])
                label = c["label"]
                syms = list(st.getSymbols(addr))
                if any(s.getName() == label for s in syms):
                    skip += 1
                    continue
                # Conservative: if a different canonical g_vtblT* already exists at addr, skip.
                conflict = any(
                    s.getName().startswith("g_vtblT") and s.getName() != label for s in syms
                )
                if conflict:
                    skip += 1
                    continue
                try:
                    sym = st.createLabel(addr, label, SourceType.USER_DEFINED)
                    sym.setPrimary()
                    ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {c['vtbl_addr']} {label} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("extract vtbl labels from named ctors", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
