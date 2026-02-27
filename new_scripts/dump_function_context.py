#!/usr/bin/env python3
"""
Dump compact function context for address candidates.

Usage:
  .venv/bin/python new_scripts/dump_function_context.py [--full | --max-lines N] <addr_or_csv> [addr_or_csv...]

Inputs:
  - Hex addresses (0x004bfb20)
  - CSV files with one of columns:
      address | callee_addr | caller_addr
"""

from __future__ import annotations

import csv
import sys
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
    t = text.strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def parse_inputs(argv: list[str]) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()

    def add(v: int):
        if v not in seen:
            seen.add(v)
            out.append(v)

    for token in argv:
        p = Path(token)
        if p.exists() and p.suffix.lower() == ".csv":
            with p.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    raw = (
                        (row.get("address") or "").strip()
                        or (row.get("callee_addr") or "").strip()
                        or (row.get("caller_addr") or "").strip()
                    )
                    if not raw:
                        continue
                    try:
                        add(parse_hex(raw))
                    except Exception:
                        continue
            continue
        add(parse_hex(token))
    return out


def safe_get_string(program, to_addr) -> str | None:
    listing = program.getListing()
    d = listing.getDataAt(to_addr)
    if d is None:
        return None
    val = d.getValue()
    if val is None:
        return None
    s = str(val)
    if not s:
        return None
    if "??" in s:
        return None
    if len(s) > 200:
        s = s[:200] + "..."
    return s


def decompile_text(ifc, func) -> str:
    res = ifc.decompileFunction(func, 20, None)
    if not res.decompileCompleted():
        return "<decompile-failed>"
    return str(res.getDecompiledFunction().getC())


def summarize_c(c_code: str, max_lines: int) -> str:
    lines = [ln.rstrip() for ln in c_code.splitlines() if ln.strip()]
    if max_lines <= 0:
        return "\n".join(lines)
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head = lines[: max_lines - 3]
    tail = lines[-2:]
    return "\n".join(head + ["/* ... */"] + tail)


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: dump_function_context.py [--full | --max-lines N] <addr_or_csv> [addr_or_csv...]"
        )
        return 1

    root = Path(__file__).resolve().parents[1]
    max_lines = 24
    sources: list[str] = []
    i = 1
    while i < len(sys.argv):
        tok = sys.argv[i]
        if tok == "--full":
            max_lines = 0
            i += 1
            continue
        if tok == "--max-lines":
            if i + 1 >= len(sys.argv):
                print("--max-lines requires a value")
                return 1
            try:
                max_lines = int(sys.argv[i + 1])
            except Exception:
                print(f"invalid --max-lines value: {sys.argv[i + 1]}")
                return 1
            i += 2
            continue
        sources.append(tok)
        i += 1

    addrs = parse_inputs(sources)
    if not addrs:
        print("no addresses parsed")
        return 1

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()

        ifc = DecompInterface()
        ifc.openProgram(program)

        for addr_int in addrs:
            addr = af.getAddress(f"0x{addr_int:08x}")
            func = fm.getFunctionAt(addr)
            if func is None:
                print(f"\n=== 0x{addr_int:08x} ===")
                print("function: <missing>")
                continue

            called = {}
            strings = []
            ins_it = listing.getInstructions(func.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                text = str(ins)
                if text.startswith("CALL "):
                    for ref in ins.getReferencesFrom():
                        cf = fm.getFunctionAt(ref.getToAddress())
                        if cf is not None:
                            called[str(cf.getEntryPoint())] = cf.getName()
                for ref in ins.getReferencesFrom():
                    if ref.getReferenceType().isData():
                        sval = safe_get_string(program, ref.getToAddress())
                        if sval:
                            strings.append((str(ref.getToAddress()), sval))

            c_code = decompile_text(ifc, func)
            print(f"\n=== 0x{addr_int:08x} {func.getName()} ===")
            print(f"signature: {func.getSignature()}")
            if called:
                called_items = sorted(called.items(), key=lambda kv: kv[0])
                print("callees:")
                for ep, nm in called_items[:30]:
                    print(f"  - {ep} {nm}")
                if len(called_items) > 30:
                    print(f"  - ... ({len(called_items) - 30} more)")
            else:
                print("callees: <none>")

            if strings:
                uniq = []
                seen = set()
                for a, s in strings:
                    key = (a, s)
                    if key in seen:
                        continue
                    seen.add(key)
                    uniq.append((a, s))
                print("strings:")
                for a, s in uniq[:12]:
                    print(f"  - {a}: {s}")
                if len(uniq) > 12:
                    print(f"  - ... ({len(uniq) - 12} more)")
            else:
                print("strings: <none>")

            print("decomp:")
            print(summarize_c(c_code, max_lines))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
