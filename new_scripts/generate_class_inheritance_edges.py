#!/usr/bin/env python3
"""
Generate conservative class inheritance edge candidates from:
  1) ctor vtable write order (base vtbl write before derived vtbl write),
  2) dtor call chains (derived dtor calls base dtor).

Output CSV columns:
  base_class,derived_class,evidence_kind,confidence,function_name,function_addr,evidence_detail

Usage:
  .venv/bin/python new_scripts/generate_class_inheritance_edges.py \
    --out tmp_decomp/class_inheritance_edges_batch357.csv
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

RX_CTOR_CLASS = re.compile(r"^Construct(T[A-Za-z0-9_]+)")
RX_DTOR_CLASS = re.compile(r"^Destruct(T[A-Za-z0-9_]+)")
RX_MOV_VTBL = re.compile(r"^MOV dword ptr \[[^\]]+\],0x00([0-9A-Fa-f]{6})$")
RX_HEX_IN_C = re.compile(r"0x00([0-9A-Fa-f]{6})")
RX_VTBL_SYM_IN_C = re.compile(r"\bg_vtblT[A-Za-z0-9_]+\b")


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_class_from_ctor(name: str) -> str | None:
    m = RX_CTOR_CLASS.match(name)
    if not m:
        return None
    return normalize_class_name(m.group(1))


def parse_class_from_dtor(name: str) -> str | None:
    m = RX_DTOR_CLASS.match(name)
    if not m:
        return None
    return normalize_class_name(m.group(1))


def normalize_class_name(cls: str) -> str:
    out = cls
    # Conservative suffix normalization for common dtor/ctor implementation labels.
    for suffix in ("AndMaybeFree", "BaseState", "Core"):
        if out.endswith(suffix) and len(out) > len("T") + len(suffix):
            out = out[: -len(suffix)]
    return out


def first_n_instruction_strings(listing, func, n: int = 24) -> list[str]:
    out: list[str] = []
    it = listing.getInstructions(func.getBody(), True)
    while it.hasNext() and len(out) < n:
        out.append(str(it.next()))
    return out


def collect_vtbl_symbols(program) -> dict[int, str]:
    st = program.getSymbolTable()
    out: dict[int, str] = {}
    it = st.getAllSymbols(True)
    while it.hasNext():
        sym = it.next()
        name = sym.getName()
        if not name.startswith("g_vtblT"):
            continue
        cls = name.replace("g_vtbl", "", 1)
        out[sym.getAddress().getOffset() & 0xFFFFFFFF] = cls
    return out


def decompile_text(ifc, func) -> str:
    try:
        res = ifc.decompileFunction(func, 30, None)
        if not res.decompileCompleted():
            return ""
        return str(res.getDecompiledFunction().getC())
    except Exception:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_csv = Path(args.out)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, int]] = set()

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        fm = program.getFunctionManager()
        listing = program.getListing()
        vtbl_addr_to_class = collect_vtbl_symbols(program)

        ifc = DecompInterface()
        ifc.openProgram(program)

        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            fname = f.getName()
            faddr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
            ns = f.getParentNamespace()
            ns_name = ns.getName() if ns is not None else ""

            # ctor-derived evidence from vtable write order
            d_ctor = parse_class_from_ctor(fname)
            if d_ctor is not None:
                ins = first_n_instruction_strings(listing, f, 24)
                vtbl_seq: list[str] = []
                for line in ins:
                    m = RX_MOV_VTBL.match(line)
                    if not m:
                        continue
                    addr = int("00" + m.group(1), 16) & 0xFFFFFFFF
                    cls = vtbl_addr_to_class.get(addr)
                    if cls:
                        if not vtbl_seq or vtbl_seq[-1] != cls:
                            vtbl_seq.append(cls)

                # Fallback to decompiled constants if disassembly pattern misses.
                if len(vtbl_seq) < 2:
                    c_code = decompile_text(ifc, f)
                    if c_code:
                        for m in RX_HEX_IN_C.finditer(c_code):
                            addr = int("00" + m.group(1), 16) & 0xFFFFFFFF
                            cls = vtbl_addr_to_class.get(addr)
                            if cls:
                                if not vtbl_seq or vtbl_seq[-1] != cls:
                                    vtbl_seq.append(cls)

                if len(vtbl_seq) >= 2:
                    # Use the last occurrence of derived in sequence and previous class as base.
                    if d_ctor in vtbl_seq:
                        i = max(i for i, c in enumerate(vtbl_seq) if c == d_ctor)
                        if i > 0:
                            base = vtbl_seq[i - 1]
                            if base != d_ctor:
                                key = (base, d_ctor, "ctor_vtbl_order", faddr)
                                if key not in seen:
                                    seen.add(key)
                                    rows.append(
                                        {
                                            "base_class": base,
                                            "derived_class": d_ctor,
                                            "evidence_kind": "ctor_vtbl_order",
                                            "confidence": "high",
                                            "function_name": fname,
                                            "function_addr": f"0x{faddr:08x}",
                                            "evidence_detail": " -> ".join(vtbl_seq[:6]),
                                        }
                                    )
                    else:
                        # Keep a weaker edge between first two observed classes.
                        base, derived = vtbl_seq[0], vtbl_seq[1]
                        if base != derived:
                            key = (base, derived, "ctor_vtbl_order_weak", faddr)
                            if key not in seen:
                                seen.add(key)
                                rows.append(
                                    {
                                        "base_class": base,
                                        "derived_class": derived,
                                        "evidence_kind": "ctor_vtbl_order_weak",
                                        "confidence": "medium",
                                        "function_name": fname,
                                        "function_addr": f"0x{faddr:08x}",
                                        "evidence_detail": " -> ".join(vtbl_seq[:6]),
                                    }
                                )

            # dtor-derived evidence from direct dtor-to-dtor calls
            d_dtor = parse_class_from_dtor(fname)
            if d_dtor is not None:
                it = listing.getInstructions(f.getBody(), True)
                called_classes: list[str] = []
                while it.hasNext():
                    ins = it.next()
                    if str(ins.getMnemonicString()).upper() != "CALL":
                        continue
                    refs = ins.getReferencesFrom()
                    for ref in refs:
                        callee = fm.getFunctionAt(ref.getToAddress())
                        if callee is None:
                            continue
                        b = parse_class_from_dtor(callee.getName())
                        if b and b != d_dtor:
                            called_classes.append(b)
                if called_classes:
                    base = called_classes[-1]
                    key = (base, d_dtor, "dtor_calls_base_dtor", faddr)
                    if key not in seen:
                        seen.add(key)
                        rows.append(
                            {
                                "base_class": base,
                                "derived_class": d_dtor,
                                "evidence_kind": "dtor_calls_base_dtor",
                                "confidence": "medium",
                                "function_name": fname,
                                "function_addr": f"0x{faddr:08x}",
                                "evidence_detail": ";".join(called_classes[:6]),
                            }
                        )

            # Decompiler g_vtbl symbol sequence evidence (broad but filtered).
            # This catches patterns where absolute PTR_LAB constants aren't emitted.
            if (
                fname.startswith(("Construct", "Create", "Destruct"))
                or ns_name.startswith("T")
                or fname.startswith("FUN_")
            ):
                c_code = decompile_text(ifc, f)
                if c_code:
                    seq: list[str] = []
                    for m in RX_VTBL_SYM_IN_C.finditer(c_code):
                        cls = normalize_class_name(m.group(0).replace("g_vtbl", "", 1))
                        if not seq or seq[-1] != cls:
                            seq.append(cls)

                    if 2 <= len(seq) <= 4:
                        # Skip noisy paths with repeated classes.
                        if len(set(seq)) == len(seq):
                            if fname.startswith("Destruct"):
                                # dtor order: derived -> base -> base2 ...
                                for i in range(len(seq) - 1):
                                    derived = seq[i]
                                    base = seq[i + 1]
                                    if base != derived:
                                        key = (base, derived, "decomp_vtbl_seq_dtor", faddr)
                                        if key not in seen:
                                            seen.add(key)
                                            rows.append(
                                                {
                                                    "base_class": base,
                                                    "derived_class": derived,
                                                    "evidence_kind": "decomp_vtbl_seq_dtor",
                                                    "confidence": "high",
                                                    "function_name": fname,
                                                    "function_addr": f"0x{faddr:08x}",
                                                    "evidence_detail": " -> ".join(seq),
                                                }
                                            )
                            elif fname.startswith(("Construct", "Create")):
                                # ctor/create order tends to be base -> derived.
                                for i in range(len(seq) - 1):
                                    base = seq[i]
                                    derived = seq[i + 1]
                                    if base != derived:
                                        key = (base, derived, "decomp_vtbl_seq_ctor", faddr)
                                        if key not in seen:
                                            seen.add(key)
                                            rows.append(
                                                {
                                                    "base_class": base,
                                                    "derived_class": derived,
                                                    "evidence_kind": "decomp_vtbl_seq_ctor",
                                                    "confidence": "medium",
                                                    "function_name": fname,
                                                    "function_addr": f"0x{faddr:08x}",
                                                    "evidence_detail": " -> ".join(seq),
                                                }
                                            )

    rows.sort(
        key=lambda r: (
            r["base_class"],
            r["derived_class"],
            {"high": 0, "medium": 1, "low": 2}.get(r["confidence"], 9),
            r["function_addr"],
        )
    )
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "base_class",
                "derived_class",
                "evidence_kind",
                "confidence",
                "function_name",
                "function_addr",
                "evidence_detail",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[done] out={out_csv}")
    print(f"[done] rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
