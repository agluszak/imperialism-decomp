#!/usr/bin/env python3
"""
Trace startup/window-message WinAPI usage and emit caller mapping.

Focus APIs:
  RegisterClassA/W, RegisterClassExA/W, CreateWindowExA/W,
  GetMessageA/W, TranslateMessage, DispatchMessageA/W.

Outputs:
  - CSV mapping api -> caller functions
  - Optional rename-candidate CSV for unresolved callers
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

API_HINTS = {
    "RegisterClassA": "RegisterWindowClassAndInitRuntime",
    "RegisterClassW": "RegisterWindowClassAndInitRuntime",
    "RegisterClassExA": "RegisterWindowClassExAndInitRuntime",
    "RegisterClassExW": "RegisterWindowClassExAndInitRuntime",
    "CreateWindowExA": "CreateMainWindowAndUiRoot",
    "CreateWindowExW": "CreateMainWindowAndUiRoot",
    "GetMessageA": "RunMainMessagePump",
    "GetMessageW": "RunMainMessagePump",
    "TranslateMessage": "RunMainMessagePump",
    "DispatchMessageA": "RunMainMessagePump",
    "DispatchMessageW": "RunMainMessagePump",
}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def is_unresolved(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_") or name.startswith("Cluster_")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/startup_winapi_callers.csv",
        help="Detailed API->caller mapping CSV",
    )
    ap.add_argument(
        "--out-rename-csv",
        default="tmp_decomp/startup_winapi_unresolved_rename_candidates.csv",
        help="Rename candidate CSV for unresolved callers",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    out_csv = Path(args.out_csv)
    out_rename_csv = Path(args.out_rename_csv)
    root = Path(args.project_root).resolve()

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []
    rename_rows = []
    caller_to_apis: dict[str, set[str]] = defaultdict(set)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        st = program.getSymbolTable()

        ext_syms = defaultdict(list)
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            s = sit.next()
            nm = s.getName()
            if nm in API_HINTS:
                ext_syms[nm].append(s)

        for api_name, syms in sorted(ext_syms.items()):
            for sym in syms:
                refs = rm.getReferencesTo(sym.getAddress())
                for ref in refs:
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    if caller is None:
                        continue
                    c_ep = str(caller.getEntryPoint())
                    c_nm = caller.getName()
                    rows.append(
                        {
                            "api_name": api_name,
                            "api_addr": str(sym.getAddress()),
                            "caller_addr": c_ep,
                            "caller_name": c_nm,
                            "from_addr": str(ref.getFromAddress()),
                            "is_unresolved": "1" if is_unresolved(c_nm) else "0",
                        }
                    )
                    caller_to_apis[c_ep].add(api_name)

        for c_ep, apis in sorted(caller_to_apis.items()):
            caller = fm.getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(c_ep))
            if caller is None:
                continue
            old_name = caller.getName()
            if not is_unresolved(old_name):
                continue

            # Prefer broader names when both registration and pump APIs appear.
            apis_sorted = sorted(apis)
            if any(a.startswith("RegisterClass") for a in apis_sorted) and any(
                a.startswith("CreateWindowEx") for a in apis_sorted
            ):
                base = "InitializeMainWindowClassAndCreateMainWindow"
            elif any(a.startswith("CreateWindowEx") for a in apis_sorted):
                base = "CreateMainWindowAndUiRoot"
            elif any(a.startswith("GetMessage") or a.startswith("DispatchMessage") for a in apis_sorted):
                base = "RunMainMessagePump"
            elif any(a.startswith("RegisterClass") for a in apis_sorted):
                base = "RegisterWindowClassAndInitRuntime"
            else:
                continue

            hex_part = c_ep[2:].lower() if c_ep.startswith("0x") else c_ep.lower()
            new_name = f"{base}_{hex_part}"
            rename_rows.append(
                {
                    "address": c_ep if c_ep.startswith("0x") else f"0x{int(c_ep,16):08x}",
                    "new_name": new_name,
                    "comment": f"[StartupWinApi] inferred from APIs: {','.join(apis_sorted)}",
                }
            )

    rows.sort(key=lambda r: (r["api_name"], r["caller_addr"], r["from_addr"]))
    rename_rows.sort(key=lambda r: r["address"])

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "api_name",
                "api_addr",
                "caller_addr",
                "caller_name",
                "from_addr",
                "is_unresolved",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    with out_rename_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(rename_rows)

    print(f"[saved] {out_csv} rows={len(rows)}")
    print(f"[saved] {out_rename_csv} rows={len(rename_rows)}")
    for r in rename_rows[:120]:
        print(f"{r['address']},{r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
