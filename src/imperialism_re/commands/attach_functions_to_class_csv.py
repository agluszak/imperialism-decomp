#!/usr/bin/env python3
"""
Attach functions to class namespaces from CSV rows.

Expected CSV columns:
  - address (required)
  - class_name (required)
  - new_name (optional)
  - reason (optional; informational only)

Usage:
  uv run impk attach_functions_to_class_csv \
    --in-csv tmp_decomp/batch_wave_class_attach.csv \
    --apply
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_optional_hex


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--apply", action="store_true", help="Write changes")
    ap.add_argument(
        "--project-root",
        default=default_project_root(),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    in_csv = Path(args.in_csv)
    if not in_csv.is_absolute():
        in_csv = root / in_csv
    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    rows = _read_rows(in_csv)
    if not rows:
        print(f"[done] no rows in {in_csv}")
        return 0

    with open_program(root) as program:
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            cls = it_cls.next()
            class_map[cls.getName()] = cls

        plans = []
        fail = 0
        for row in rows:
            addr_i = parse_optional_hex((row.get("address") or "").strip())
            class_name = (row.get("class_name") or "").strip()
            new_name = (row.get("new_name") or "").strip()
            reason = (row.get("reason") or "").strip()
            if addr_i is None or not class_name:
                fail += 1
                print(f"[skip-row] missing address/class_name row={row}")
                continue

            addr = af.getAddress(f"0x{addr_i:08x}")
            fn = fm.getFunctionAt(addr)
            if fn is None:
                fail += 1
                print(f"[skip-row] no function at 0x{addr_i:08x}")
                continue

            cls = class_map.get(class_name)
            if cls is None:
                fail += 1
                print(f"[skip-row] missing class namespace: {class_name} (0x{addr_i:08x})")
                continue

            cur_ns = fn.getParentNamespace()
            cur_ns_name = "<none>" if cur_ns is None else cur_ns.getName()
            plans.append(
                {
                    "addr_i": addr_i,
                    "fn": fn,
                    "cur_ns": cur_ns,
                    "cur_ns_name": cur_ns_name,
                    "dst_ns": cls,
                    "dst_name": class_name,
                    "new_name": new_name,
                    "reason": reason,
                }
            )

        print(f"[plan] rows={len(rows)} valid={len(plans)} invalid={fail} apply={args.apply}")
        for item in plans[:300]:
            fn = item["fn"]
            print(
                f"  0x{item['addr_i']:08x} {item['cur_ns_name']}::{fn.getName()} "
                f"-> {item['dst_name']}::{item['new_name'] or fn.getName()} "
                f"{'(' + item['reason'] + ')' if item['reason'] else ''}"
            )
        if len(plans) > 300:
            print(f"... ({len(plans)-300} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Attach functions to class namespaces from CSV")
        ns_ok = ns_skip = ns_fail = 0
        rn_ok = rn_skip = rn_fail = 0
        try:
            for item in plans:
                fn = item["fn"]
                dst_ns = item["dst_ns"]
                cur_ns = item["cur_ns"]
                try:
                    if cur_ns == dst_ns:
                        ns_skip += 1
                    elif cur_ns != global_ns and (cur_ns is not None and cur_ns.getName() != "Global"):
                        ns_skip += 1
                        print(
                            f"[ns-skip] 0x{item['addr_i']:08x} {fn.getName()} "
                            f"already in non-global namespace {item['cur_ns_name']}"
                        )
                    else:
                        fn.setParentNamespace(dst_ns)
                        ns_ok += 1
                except Exception as ex:
                    ns_fail += 1
                    print(f"[ns-fail] 0x{item['addr_i']:08x} {fn.getName()} err={ex}")
                    continue

                new_name = item["new_name"]
                if not new_name:
                    continue
                try:
                    if fn.getName() == new_name:
                        rn_skip += 1
                    else:
                        fn.setName(new_name, SourceType.USER_DEFINED)
                        rn_ok += 1
                except Exception as ex:
                    rn_fail += 1
                    print(f"[rename-fail] 0x{item['addr_i']:08x} {fn.getName()} -> {new_name} err={ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("attach functions to class namespaces from csv", None)
        print(
            f"[done] ns_ok={ns_ok} ns_skip={ns_skip} ns_fail={ns_fail} "
            f"rename_ok={rn_ok} rename_skip={rn_skip} rename_fail={rn_fail}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
