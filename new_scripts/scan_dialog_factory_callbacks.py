#!/usr/bin/env python3
"""
Scan a dialog-factory initializer and list registered callback functions.

Usage example:
  .venv/bin/python new_scripts/scan_dialog_factory_callbacks.py \
    --ghidra-install /home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC \
    --project-root /home/andrzej.gluszak/code/personal/imperialism_knowledge \
    --project-name imperialism-decomp \
    --program /Imperialism.exe \
    --initializer 0x00405781 \
    --constants 0x7d8,0x7de,2101,2102,2111,2128
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable
import re

import pyghidra


def parse_int_list(raw: str) -> list[int]:
    vals: list[int] = []
    for token in raw.split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token.startswith("0x"):
            vals.append(int(token, 16))
        else:
            vals.append(int(token, 10))
    return vals


def iter_instructions(listing, body) -> Iterable:
    it = listing.getInstructions(body, True)
    for ins in it:
        yield ins


def open_project_resilient(project_root: Path, project_name: str):
    """Open project with fallback modes in case of lock owner edge-cases."""
    try:
        return pyghidra.open_project(str(project_root), project_name, create=False)
    except Exception:
        # Fallback to direct manager call with alternate open flags.
        from ghidra.framework.model import ProjectLocator
        from ghidra.pyghidra import PyGhidraProjectManager

        pm = PyGhidraProjectManager()
        loc = ProjectLocator(str(project_root), project_name)
        for restore, flag in ((False, True), (False, False), (True, False), (True, True)):
            try:
                return pm.openProject(loc, restore, flag)
            except Exception:
                continue
        raise


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ghidra-install", required=True, type=Path)
    ap.add_argument("--project-root", required=True, type=Path)
    ap.add_argument("--project-name", required=True)
    ap.add_argument("--program", default="/Imperialism.exe")
    ap.add_argument(
        "--initializer",
        default="0x00405781",
        help="Address of InitializeTurnEventDialogFactoryRegistry-like function",
    )
    ap.add_argument(
        "--constants",
        default="0x7d8,0x7de,2101,2102,2111,2128",
        help="Comma-separated constants to detect in callback bodies",
    )
    args = ap.parse_args()

    interesting = set(parse_int_list(args.constants))
    pyghidra.start(install_dir=args.ghidra_install)

    project = open_project_resilient(args.project_root, args.project_name)
    try:
        with pyghidra.program_context(project, args.program) as program:
            af = program.getAddressFactory().getDefaultAddressSpace()
            fm = program.getFunctionManager()
            listing = program.getListing()

            init_addr = af.getAddress(args.initializer.lower())
            init_fn = fm.getFunctionAt(init_addr)
            if init_fn is None:
                raise RuntimeError(f"No function at initializer {args.initializer}")

            print(f"initializer={init_fn.getName()} @ {init_fn.getEntryPoint()}")

            # Recover callback addresses from decompiled RegisterDialogFactoryCallback lines.
            callbacks: list[int] = []
            try:
                from ghidra.app.decompiler import DecompInterface
                from ghidra.util.task import ConsoleTaskMonitor

                ifc = DecompInterface()
                if ifc.openProgram(program):
                    res = ifc.decompileFunction(init_fn, 30, ConsoleTaskMonitor())
                    if res.decompileCompleted():
                        code = res.getDecompiledFunction().getC()
                        for hit in re.findall(
                            r"RegisterDialogFactoryCallback\([^,]+,\s*(0x[0-9a-fA-F]+)\)",
                            code,
                        ):
                            callbacks.append(int(hit, 16))
            except Exception:
                # Fall back to instruction pattern recovery below.
                pass

            # Fallback: recover callback addresses from RegisterDialogFactoryCallback callsites.
            insns = list(iter_instructions(listing, init_fn.getBody()))
            if not callbacks:
                for idx, ins in enumerate(insns):
                    if ins.getMnemonicString().upper() != "CALL":
                        continue
                    refs = ins.getReferencesFrom()
                    target_fn_name = None
                    if refs and len(refs) > 0:
                        to_addr = refs[0].getToAddress()
                        tf = fm.getFunctionAt(to_addr)
                        if tf is not None:
                            target_fn_name = tf.getName()
                    if not target_fn_name or "RegisterDialogFactoryCallback" not in target_fn_name:
                        continue

                    cb_addr = None
                    for j in range(max(0, idx - 6), idx):
                        prev = insns[j]
                        if prev.getMnemonicString().upper() != "PUSH":
                            continue
                        op = prev.getOpObjects(0)
                        if not op or len(op) == 0:
                            continue
                        obj = op[0]
                        val = None
                        if hasattr(obj, "getValue"):
                            try:
                                val = int(obj.getValue())
                            except Exception:
                                val = None
                        if val is None:
                            continue
                        cand = af.getAddress(hex(val))
                        if cand is None:
                            continue
                        fn = fm.getFunctionAt(cand)
                        if fn is not None:
                            cb_addr = val
                    if cb_addr is not None:
                        callbacks.append(cb_addr)

            # Keep unique order.
            seen = set()
            uniq_callbacks: list[int] = []
            for cb in callbacks:
                if cb in seen:
                    continue
                seen.add(cb)
                uniq_callbacks.append(cb)

            print(f"callbacks_found={len(uniq_callbacks)}")
            for cb in uniq_callbacks:
                addr = af.getAddress(hex(cb))
                fn = fm.getFunctionAt(addr)
                name = fn.getName() if fn else "<no_function>"
                hits: list[str] = []
                if fn is not None:
                    for ins in iter_instructions(listing, fn.getBody()):
                        for op_idx in range(ins.getNumOperands()):
                            for obj in ins.getOpObjects(op_idx):
                                if hasattr(obj, "getValue"):
                                    try:
                                        v = int(obj.getValue())
                                    except Exception:
                                        continue
                                    if v in interesting:
                                        hits.append(hex(v))
                uniq_hits = sorted(set(hits), key=lambda x: int(x, 16))
                print(f"0x{cb:08x} | {name} | hits={','.join(uniq_hits) if uniq_hits else '-'}")
    finally:
        project.close()


if __name__ == "__main__":
    main()
