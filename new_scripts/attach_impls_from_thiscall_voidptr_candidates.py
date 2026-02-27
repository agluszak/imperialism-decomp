#!/usr/bin/env python3
"""
Attach implementation targets from thiscall-void* thunk candidate CSV.

Input:
  CSV from find_thiscall_voidptr_classpass_candidates.py
  (columns: address,name,dominant_class,dominant_calls,class_calls_total,dominant_ratio,...)

Behavior:
  - For each candidate row, resolve function at `address`.
  - Follow simple forwarder chain (JMP or CALL;RET) up to --max-depth.
  - Use terminal function as implementation target.
  - Attach target to row's dominant_class when safety gates pass.

Safety gates:
  - dominant_ratio >= --min-ratio
  - class_calls_total >= --min-class-calls
  - dominant_class exists as class namespace
  - target currently in Global namespace (unless --allow-non-global)
  - skip names matching --target-deny-regex

Optional:
  - --retype-pthis: for attached targets, if __thiscall and first param is void*,
    retype first param to <dominant_class>* pThis.

Usage:
  .venv/bin/python new_scripts/attach_impls_from_thiscall_voidptr_candidates.py \
    --in-csv tmp_decomp/thiscall_voidptr_classpass_candidates.csv

  .venv/bin/python new_scripts/attach_impls_from_thiscall_voidptr_candidates.py \
    --in-csv tmp_decomp/thiscall_voidptr_classpass_candidates.csv --apply --retype-pthis
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


def parse_addr_hex(text: str):
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def addr_hex(v: int):
    return f"0x{v:08x}"


def is_global_ns(ns, global_ns):
    return ns is None or ns == global_ns or ns.getName() == "Global"


def get_instructions(listing, body):
    out = []
    it = listing.getInstructions(body, True)
    while it.hasNext():
        out.append(it.next())
    return out


def resolve_first_internal_target(fm, ins):
    refs = ins.getReferencesFrom()
    for ref in refs:
        callee = fm.getFunctionAt(ref.getToAddress())
        if callee is None:
            continue
        ep_txt = str(callee.getEntryPoint())
        if ep_txt.startswith("EXTERNAL:"):
            continue
        return callee
    return None


def simple_forward_target(program, func):
    listing = program.getListing()
    fm = program.getFunctionManager()
    insns = get_instructions(listing, func.getBody())
    if len(insns) == 1 and str(insns[0].getMnemonicString()).upper() == "JMP":
        return resolve_first_internal_target(fm, insns[0]), "JMP"
    if (
        len(insns) == 2
        and str(insns[0].getMnemonicString()).upper() == "CALL"
        and str(insns[1].getMnemonicString()).upper() == "RET"
    ):
        return resolve_first_internal_target(fm, insns[0]), "CALL_RET"
    return None, None


def is_void_pointer(dt):
    nm = (dt.getName() or "").replace(" ", "").lower()
    if nm == "void*":
        return True
    if hasattr(dt, "getDataType"):
        try:
            base = dt.getDataType()
            if base is not None and (base.getName() or "").strip().lower() == "void":
                return True
        except Exception:
            pass
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--in-csv",
        default="tmp_decomp/thiscall_voidptr_classpass_candidates.csv",
        help="Input candidates CSV",
    )
    ap.add_argument("--apply", action="store_true", help="Write namespace/type changes")
    ap.add_argument("--max-depth", type=int, default=4, help="Forwarder chain max depth")
    ap.add_argument("--min-ratio", type=float, default=0.75)
    ap.add_argument("--min-class-calls", type=int, default=2)
    ap.add_argument("--allow-non-global", action="store_true")
    ap.add_argument(
        "--target-deny-regex",
        default=r"^(Dtor_|Ctor_|FID_conflict|`)",
        help="Skip targets matching this regex",
    )
    ap.add_argument("--retype-pthis", action="store_true")
    ap.add_argument("--max-print", type=int, default=120)
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    in_csv = (root / args.in_csv).resolve()
    deny_re = re.compile(args.target_deny_regex) if args.target_deny_regex else None

    if not in_csv.exists():
        print(f"[error] missing csv: {in_csv}")
        return 1

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8")))
    if not rows:
        print("[done] no rows in input csv")
        return 0

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import PointerDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        st = program.getSymbolTable()
        dtm = program.getDataTypeManager()
        global_ns = program.getGlobalNamespace()

        class_map = {}
        it_cls = st.getClassNamespaces()
        while it_cls.hasNext():
            ns = it_cls.next()
            class_map[ns.getName()] = ns

        dt_by_class = {}
        dt_it = dtm.getAllDataTypes()
        all_dt = []
        while dt_it.hasNext():
            all_dt.append(dt_it.next())
        for cls in class_map:
            for dt in all_dt:
                if dt.getName() == cls:
                    dt_by_class[cls] = dt
                    break

        plans = []
        skip_reason = {
            "bad_ratio_or_calls": 0,
            "missing_class": 0,
            "missing_func": 0,
            "deny_target_name": 0,
            "non_global_target": 0,
            "self_terminal": 0,
        }

        for row in rows:
            try:
                ratio = float(row.get("dominant_ratio", "0") or "0")
                class_calls = int(row.get("class_calls_total", "0") or "0")
            except Exception:
                skip_reason["bad_ratio_or_calls"] += 1
                continue

            if ratio < args.min_ratio or class_calls < args.min_class_calls:
                skip_reason["bad_ratio_or_calls"] += 1
                continue

            cls = (row.get("dominant_class") or "").strip()
            cls_ns = class_map.get(cls)
            if cls_ns is None:
                skip_reason["missing_class"] += 1
                continue

            src_addr = parse_addr_hex(row["address"])
            src = fm.getFunctionAt(af.getAddress(addr_hex(src_addr)))
            if src is None:
                skip_reason["missing_func"] += 1
                continue

            cur = src
            seen = {src_addr}
            hops = 0
            last_shape = ""
            while hops < args.max_depth:
                nxt, shape = simple_forward_target(program, cur)
                if nxt is None:
                    break
                ep = int(nxt.getEntryPoint().getOffset() & 0xFFFFFFFF)
                if ep in seen:
                    break
                seen.add(ep)
                cur = nxt
                last_shape = shape
                hops += 1

            tgt = cur
            tgt_addr = int(tgt.getEntryPoint().getOffset() & 0xFFFFFFFF)
            if tgt_addr == src_addr:
                skip_reason["self_terminal"] += 1
                continue

            tgt_name = tgt.getName()
            if deny_re and deny_re.search(tgt_name):
                skip_reason["deny_target_name"] += 1
                continue

            tgt_ns = tgt.getParentNamespace()
            if (not args.allow_non_global) and (not is_global_ns(tgt_ns, global_ns)):
                skip_reason["non_global_target"] += 1
                continue

            plans.append(
                {
                    "src_addr": src_addr,
                    "src_name": src.getName(),
                    "tgt_addr": tgt_addr,
                    "tgt_name": tgt_name,
                    "class_name": cls,
                    "class_ns": cls_ns,
                    "hops": hops,
                    "last_shape": last_shape,
                    "ratio": ratio,
                    "class_calls": class_calls,
                    "target_func": tgt,
                }
            )

        # Deduplicate by target address, keeping strongest ratio/class_calls/hops.
        by_tgt = {}
        for p in plans:
            key = p["tgt_addr"]
            old = by_tgt.get(key)
            if old is None:
                by_tgt[key] = p
                continue
            old_score = (old["ratio"], old["class_calls"], old["hops"])
            new_score = (p["ratio"], p["class_calls"], p["hops"])
            if new_score > old_score:
                by_tgt[key] = p

        final_plans = [by_tgt[k] for k in sorted(by_tgt.keys())]

        print(
            f"[candidates] input_rows={len(rows)} attach_targets={len(final_plans)} "
            f"min_ratio={args.min_ratio:.2f} min_class_calls={args.min_class_calls}"
        )
        for k, v in skip_reason.items():
            print(f"[skip] {k}={v}")
        for p in final_plans[: args.max_print]:
            print(
                f"  {addr_hex(p['src_addr'])} {p['src_name']} -> "
                f"{addr_hex(p['tgt_addr'])} {p['tgt_name']} -> {p['class_name']} "
                f"hops={p['hops']} ratio={p['ratio']:.2f}"
            )
        if len(final_plans) > args.max_print:
            print(f"  ... ({len(final_plans) - args.max_print} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        tx = program.startTransaction("Attach impl targets from thiscall void* candidates")
        ns_ok = ns_skip = ns_fail = 0
        type_ok = type_skip = type_fail = 0
        try:
            for p in final_plans:
                f = p["target_func"]
                cls_ns = p["class_ns"]

                try:
                    if f.getParentNamespace() == cls_ns:
                        ns_skip += 1
                    else:
                        f.setParentNamespace(cls_ns)
                        ns_ok += 1
                except Exception as ex:
                    ns_fail += 1
                    print(f"[ns-fail] {f.getEntryPoint()} {f.getName()} -> {p['class_name']} err={ex}")
                    continue

                if not args.retype_pthis:
                    continue

                try:
                    if f.getCallingConventionName() != "__thiscall":
                        type_skip += 1
                        continue
                    params = list(f.getParameters())
                    if not params:
                        type_skip += 1
                        continue
                    if not is_void_pointer(params[0].getDataType()):
                        type_skip += 1
                        continue
                    cls_dt = dt_by_class.get(p["class_name"])
                    if cls_dt is None:
                        type_skip += 1
                        continue
                    pthis = ParameterImpl("pThis", PointerDataType(cls_dt), program, SourceType.USER_DEFINED)
                    new_params = [pthis]
                    for i in range(1, len(params)):
                        pp = params[i]
                        nm = pp.getName() or f"param_{i+1}"
                        new_params.append(ParameterImpl(nm, pp.getDataType(), program, SourceType.USER_DEFINED))
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        new_params,
                    )
                    type_ok += 1
                except Exception as ex:
                    type_fail += 1
                    print(f"[type-fail] {f.getEntryPoint()} {f.getName()} err={ex}")
        finally:
            program.endTransaction(tx, True)

        if ns_ok > 0 or type_ok > 0:
            program.save("attach impl targets from thiscall void* candidates", None)
        print(
            f"[done] ns_ok={ns_ok} ns_skip={ns_skip} ns_fail={ns_fail} "
            f"type_ok={type_ok} type_skip={type_skip} type_fail={type_fail}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
