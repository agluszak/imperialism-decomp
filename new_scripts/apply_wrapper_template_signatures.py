#!/usr/bin/env python3
"""
Apply signature templates to selected wrapper families with strict header gating.

This script is intentionally conservative: each template has a decompiled-header
regex gate, and only matching functions are updated.

Usage:
  .venv/bin/python new_scripts/apply_wrapper_template_signatures.py [--apply] [--project-root PATH]
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
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


def extract_header(c_code: str) -> str:
    m = re.search(r"^(.*?)\n\{", c_code, re.S)
    if not m:
        return ""
    lines = [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]
    return lines[-1] if lines else ""


@dataclass
class Template:
    prefix: str
    header_re: re.Pattern[str]
    cc: str
    return_kind: str  # "void" | "void_ptr"
    param_kinds: list[str]  # each: "void_ptr" | "int" | "ushort"
    param_names: list[str]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="Write signature changes")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    templates = [
        Template(
            prefix="WrapperFor_InitializeCityInteriorMinister_At",
            header_re=re.compile(r"\(\s*undefined4\s+param_1\s*\)$"),
            cc="__fastcall",
            return_kind="void",
            param_kinds=["void_ptr"],
            param_names=["pMinisterState"],
        ),
        Template(
            prefix="WrapperFor_ConstructTMinister_At",
            header_re=re.compile(r"undefined4\s*\*\s*__fastcall.*\(\s*undefined4\s*\*\s*param_1\s*\)$"),
            cc="__fastcall",
            return_kind="void_ptr",
            param_kinds=["void_ptr"],
            param_names=["pMinisterState"],
        ),
        Template(
            prefix="WrapperFor_DeserializeTMinisterBaseOrderArrayHeader_At",
            header_re=re.compile(r"void\s+__thiscall.*\(\s*int\s+param_1\s*,\s*int\s*\*\s*param_2\s*\)$"),
            cc="__thiscall",
            return_kind="void",
            param_kinds=["void_ptr"],
            param_names=["pSerializedStream"],
        ),
        Template(
            prefix="WrapperFor_SerializeTMinisterBaseOrderArrayHeader_At",
            header_re=re.compile(r".*\(\s*int\s+param_1\s*,\s*int\s*\*\s*param_2\s*\)$"),
            cc="__thiscall",
            return_kind="void",
            param_kinds=["void_ptr"],
            param_names=["pSerializedStream"],
        ),
        Template(
            prefix="WrapperFor_RefreshCityCapabilityUiHandlesForActiveNation_At",
            header_re=re.compile(r".*\(\s*int\s+param_1\s*,\s*undefined2\s+param_2\s*\)$"),
            cc="__thiscall",
            return_kind="void",
            param_kinds=["ushort"],
            param_names=["activeNationId"],
        ),
    ]

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.data import (
            IntegerDataType,
            PointerDataType,
            UnsignedShortDataType,
            VoidDataType,
        )
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        ifc = DecompInterface()
        ifc.openProgram(program)

        void_t = VoidDataType.dataType
        void_ptr = PointerDataType(VoidDataType.dataType)
        int_t = IntegerDataType.dataType
        ushort_t = UnsignedShortDataType.dataType

        def mk_param(kind: str, name: str):
            if kind == "void_ptr":
                dt = void_ptr
            elif kind == "int":
                dt = int_t
            elif kind == "ushort":
                dt = ushort_t
            else:
                raise ValueError(f"unknown param kind: {kind}")
            return ParameterImpl(name, dt, program, SourceType.USER_DEFINED)

        candidates = []
        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            n = f.getName()
            t = next((tpl for tpl in templates if n.startswith(tpl.prefix)), None)
            if t is None:
                continue
            res = ifc.decompileFunction(f, 20, None)
            if not res.decompileCompleted():
                continue
            header = extract_header(res.getDecompiledFunction().getC())
            if not t.header_re.search(header):
                continue
            candidates.append((f, t, header))

        print(f"[candidates] {len(candidates)}")
        for f, t, header in candidates:
            print(f"  {f.getEntryPoint()} {f.getName()} | {t.cc} | {header}")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Apply wrapper template signatures")
        ok = 0
        skip = 0
        fail = 0
        try:
            for f, t, _ in candidates:
                try:
                    old_sig = str(f.getSignature())
                    params = [mk_param(k, n) for k, n in zip(t.param_kinds, t.param_names)]
                    f.setCallingConvention(t.cc)
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        params,
                    )
                    f.setReturnType(void_ptr if t.return_kind == "void_ptr" else void_t, SourceType.USER_DEFINED)
                    new_sig = str(f.getSignature())
                    if new_sig == old_sig:
                        skip += 1
                    else:
                        ok += 1
                except Exception as ex:
                    fail += 1
                    print(f"[fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply wrapper template signatures", None)
        print(f"[done] ok={ok} skip={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
