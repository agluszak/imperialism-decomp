#!/usr/bin/env python3
"""
Run one unresolved-promotion wave in a single pyghidra session.

This script merges the repetitive per-wave steps:
1) apply core renames (and optional comments),
2) optionally rename direct JMP thunk mirrors to `thunk_<target>`,
3) apply core signatures,
4) apply thunk signatures (explicit mappings + optional auto-generated mappings),
5) emit post-wave quality artifacts (unresolved snapshots, strict gate, runtime gate, progress).

CSV formats:
- Renames CSV (required):
  address,new_name[,comment]
- Signatures CSV (optional):
  address,calling_convention,return_type,params
- Thunk signature mapping CSV (optional):
  address,target_addr

Usage example:
  .venv/bin/python new_scripts/run_unresolved_wave.py \
    --renames-csv tmp_decomp/batchNN_waveX_renames.csv \
    --signatures-csv tmp_decomp/batchNN_waveX_signatures.csv \
    --thunk-signatures-csv tmp_decomp/batchNN_waveX_thunk_sigs.csv \
    --auto-thunk-mirrors \
    --auto-thunk-out-csv tmp_decomp/batchNN_waveX_auto_thunks.csv \
    --unresolved-main-out-csv tmp_decomp/batch437_unresolved_0040_006f_snapshot_postXX.csv \
    --strict-gate-out-csv tmp_decomp/batch437_named_callers_with_generic_callees_superlane_strict_postXX.csv \
    --unresolved-runtime-out-csv tmp_decomp/batch437_unresolved_0060_0062_postXX.csv \
    --progress-out tmp_decomp/batch437_progress_counts_postXX.txt \
    --apply
"""

from __future__ import annotations

import argparse
import csv
import re
from functools import lru_cache
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


def parse_hex(text: str) -> int:
    t = text.strip()
    if t.lower().startswith("0x"):
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


def is_unresolved_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def is_generic_strict_callee(name: str) -> bool:
    # Keep strict-gate compatibility with existing script behavior.
    return (
        name.startswith("FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def split_pointer_type(type_name: str) -> tuple[str, int]:
    t = type_name.strip().replace(" ", "")
    stars = 0
    while t.endswith("*"):
        stars += 1
        t = t[:-1]
    return t, stars


def normalize_base_type_name(name: str) -> str:
    t = name.strip()
    t = t.replace("const ", "").replace("volatile ", "")
    t = t.replace("struct ", "").replace("class ", "")
    return t.strip()


@lru_cache(maxsize=2048)
def resolve_named_data_type(dtm, base_name: str):
    target = base_name.strip()
    if not target:
        return None
    best = None
    best_score = None
    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        try:
            if dt.getName() != target:
                continue
            cat = str(dt.getCategoryPath().getPath())
            # Prefer root/class categories first, then shortest category path.
            pri = 0 if cat in ("/", "/imperialism/classes", "/Imperialism/classes") else 1
            score = (pri, len(cat), cat)
            if best is None or score < best_score:
                best = dt
                best_score = score
        except Exception:
            continue
    return best


def build_data_type(type_name: str, dtm=None):
    from ghidra.program.model.data import (
        BooleanDataType,
        ByteDataType,
        CharDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    base_name, ptr_depth = split_pointer_type(type_name)
    base_name = normalize_base_type_name(base_name)
    base_key = base_name.lower()
    base_map = {
        "void": VoidDataType.dataType,
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "bool": BooleanDataType.dataType,
    }
    dt = base_map.get(base_key)
    if dt is None and dtm is not None:
        dt = resolve_named_data_type(dtm, base_name)
    if dt is None:
        dt = VoidDataType.dataType if ptr_depth > 0 else IntegerDataType.dataType
    for _ in range(ptr_depth):
        dt = PointerDataType(dt)
    return dt


def parse_params(raw: str):
    out: list[tuple[str, str]] = []
    txt = (raw or "").strip()
    if not txt:
        return out
    for part in txt.split(";"):
        p = part.strip()
        if not p:
            continue
        if ":" not in p:
            raise ValueError(f"invalid param entry (expected name:type): {p}")
        name, typ = p.split(":", 1)
        out.append((name.strip(), typ.strip()))
    return out


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    return list(csv.DictReader(path.open("r", encoding="utf-8", newline="")))


def single_jmp_to_target(listing, func, target_addr) -> bool:
    ins_it = listing.getInstructions(func.getBody(), True)
    ins = []
    while ins_it.hasNext():
        ins.append(ins_it.next())
        if len(ins) > 2:
            break
    if len(ins) != 1:
        return False
    if str(ins[0].getMnemonicString()).upper() != "JMP":
        return False
    flows = ins[0].getFlows()
    if flows is None or len(flows) != 1:
        return False
    return flows[0] == target_addr


def ensure_unique_name(existing_names: set[str], desired: str, fallback_suffix_addr: int) -> str:
    if desired not in existing_names:
        return desired
    base = f"{desired}_At{fallback_suffix_addr:08x}"
    cur = base
    i = 2
    while cur in existing_names:
        cur = f"{base}_{i}"
        i += 1
    return cur


def write_dict_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def build_unresolved_rows(program, lo: int, hi: int, name_regex: str) -> list[dict[str, str]]:
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    listing = program.getListing()
    af = program.getAddressFactory().getDefaultAddressSpace()
    name_re = re.compile(name_regex)

    rows: list[dict[str, str]] = []
    fit = fm.getFunctions(True)
    while fit.hasNext():
        f = fit.next()
        addr = f.getEntryPoint().getOffset() & 0xFFFFFFFF
        if addr < lo or addr > hi:
            continue
        name = f.getName()
        if not name_re.search(name):
            continue

        refs_to = rm.getReferencesTo(af.getAddress(f"0x{addr:08x}"))
        callers_named = 0
        callers_generic = 0
        callers_total = 0
        callers_set = set()
        for ref in refs_to:
            c = fm.getFunctionContaining(ref.getFromAddress())
            if c is None:
                continue
            caddr = c.getEntryPoint().getOffset() & 0xFFFFFFFF
            key = (caddr, c.getName())
            if key in callers_set:
                continue
            callers_set.add(key)
            callers_total += 1
            if is_unresolved_name(c.getName()):
                callers_generic += 1
            else:
                callers_named += 1

        instr_count = 0
        call_insn_count = 0
        callee_named = set()
        callee_generic = set()
        ins_it = listing.getInstructions(f.getBody(), True)
        while ins_it.hasNext():
            ins = ins_it.next()
            instr_count += 1
            if str(ins.getMnemonicString()).upper() != "CALL":
                continue
            call_insn_count += 1
            for ref in ins.getReferencesFrom():
                c = fm.getFunctionAt(ref.getToAddress())
                if c is None:
                    continue
                caddr_txt = str(c.getEntryPoint())
                if caddr_txt.startswith("EXTERNAL:"):
                    continue
                ctag = f"{c.getName()}@{caddr_txt}"
                if is_unresolved_name(c.getName()):
                    callee_generic.add(ctag)
                else:
                    callee_named.add(ctag)

        ns = f.getParentNamespace()
        rows.append(
            {
                "address": f"0x{addr:08x}",
                "name": name,
                "namespace": "" if ns is None else ns.getName(),
                "instruction_count": str(instr_count),
                "call_insn_count": str(call_insn_count),
                "xrefs_to_count": str(callers_total),
                "named_caller_count": str(callers_named),
                "generic_caller_count": str(callers_generic),
                "named_callee_count": str(len(callee_named)),
                "generic_callee_count": str(len(callee_generic)),
                "named_callees": ";".join(sorted(callee_named)),
                "sample_callers": ";".join(
                    sorted(f"{nm}@0x{ca:08x}" for ca, nm in callers_set)[:12]
                ),
            }
        )

    rows.sort(
        key=lambda r: (
            -int(r["named_caller_count"]),
            -int(r["xrefs_to_count"]),
            -int(r["named_callee_count"]),
            r["address"],
        )
    )
    return rows


def build_strict_gate_rows(program, caller_regex: str) -> list[dict[str, str]]:
    fm = program.getFunctionManager()
    listing = program.getListing()
    cre = re.compile(caller_regex)
    rows: list[dict[str, str]] = []

    fit = fm.getFunctions(True)
    while fit.hasNext():
        caller = fit.next()
        caller_name = caller.getName()
        if not cre.search(caller_name):
            continue

        generic: set[str] = set()
        ins_it = listing.getInstructions(caller.getBody(), True)
        while ins_it.hasNext():
            ins = ins_it.next()
            if not str(ins).startswith("CALL "):
                continue
            for ref in ins.getReferencesFrom():
                callee = fm.getFunctionAt(ref.getToAddress())
                if callee is None:
                    continue
                callee_name = callee.getName()
                if is_generic_strict_callee(callee_name):
                    generic.add(f"{callee_name}@{callee.getEntryPoint()}")

        if generic:
            rows.append(
                {
                    "caller_addr": str(caller.getEntryPoint()),
                    "caller_name": caller_name,
                    "generic_callee_count": str(len(generic)),
                    "generic_callees": ";".join(sorted(generic)),
                }
            )

    rows.sort(key=lambda r: (-int(r["generic_callee_count"]), r["caller_name"]))
    return rows


def compute_progress(program) -> dict[str, int]:
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    rx_default = re.compile(r"^(FUN_|thunk_FUN_)")

    total = renamed = default_named = 0
    fit = fm.getFunctions(True)
    while fit.hasNext():
        f = fit.next()
        total += 1
        if rx_default.match(f.getName()):
            default_named += 1
        else:
            renamed += 1

    class_desc = vtbl = tname = 0
    sit = st.getAllSymbols(True)
    while sit.hasNext():
        n = sit.next().getName()
        if n.startswith("g_pClassDescT"):
            class_desc += 1
        if n.startswith("g_vtblT"):
            if "_Slot" in n or "Candidate_" in n or "Family_" in n:
                continue
            vtbl += 1
        if n.startswith("g_szTypeNameT"):
            tname += 1

    return {
        "total_functions": total,
        "renamed_functions": renamed,
        "default_fun_or_thunk_fun": default_named,
        "class_desc_count": class_desc,
        "vtbl_count": vtbl,
        "type_name_count": tname,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--renames-csv", required=True)
    ap.add_argument("--signatures-csv")
    ap.add_argument("--thunk-signatures-csv")
    ap.add_argument("--auto-thunk-mirrors", action="store_true")
    ap.add_argument("--auto-thunk-out-csv")
    ap.add_argument("--create-missing", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))

    ap.add_argument("--unresolved-main-min", default="0x00400000")
    ap.add_argument("--unresolved-main-max", default="0x006fffff")
    ap.add_argument("--unresolved-main-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--unresolved-main-out-csv")

    ap.add_argument("--strict-caller-regex", default=r"^(?!FUN_|thunk_|Cluster_|WrapperFor_Cluster_).+")
    ap.add_argument("--strict-gate-out-csv")

    ap.add_argument("--unresolved-runtime-min", default="0x00600000")
    ap.add_argument("--unresolved-runtime-max", default="0x0062ffff")
    ap.add_argument("--unresolved-runtime-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--unresolved-runtime-out-csv")

    ap.add_argument("--progress-out")
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    renames_csv = Path(args.renames_csv)
    if not renames_csv.exists():
        print(f"missing renames csv: {renames_csv}")
        return 1
    rename_rows = load_csv_rows(renames_csv)
    sig_rows = load_csv_rows(Path(args.signatures_csv)) if args.signatures_csv else []
    thunk_sig_rows = load_csv_rows(Path(args.thunk_signatures_csv)) if args.thunk_signatures_csv else []

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()
        dtm = program.getDataTypeManager()
        monitor = ConsoleTaskMonitor()
        existing_function_names: set[str] = set()
        fit_names = fm.getFunctions(True)
        while fit_names.hasNext():
            existing_function_names.add(fit_names.next().getName())

        rename_ok = rename_skip = rename_fail = rename_cmt = created = 0
        sig_ok = sig_skip = sig_fail = 0
        tsig_ok = tsig_skip = tsig_fail = 0
        auto_thunk_rows: list[dict[str, str]] = []
        auto_thunk_sig_map: dict[int, int] = {}

        tx = None
        if args.apply:
            tx = program.startTransaction("Run unresolved wave")
        try:
            # Step 1: core renames
            for row in rename_rows:
                addr_txt = (row.get("address") or "").strip()
                new_name = (row.get("new_name") or "").strip()
                comment = (row.get("comment") or "").strip()
                if not addr_txt or not new_name:
                    rename_fail += 1
                    continue
                try:
                    addr_int = parse_hex(addr_txt)
                except Exception:
                    rename_fail += 1
                    continue
                addr = af.getAddress(f"0x{addr_int:08x}")
                func = fm.getFunctionAt(addr)
                if func is None and args.create_missing and args.apply:
                    try:
                        DisassembleCommand(addr, None, True).applyTo(program, monitor)
                        CreateFunctionCmd(None, addr, None, SourceType.USER_DEFINED).applyTo(
                            program, monitor
                        )
                        func = fm.getFunctionAt(addr)
                        if func is not None:
                            created += 1
                    except Exception:
                        pass
                if func is None:
                    rename_fail += 1
                    continue

                if args.apply:
                    if func.getName() == new_name:
                        rename_skip += 1
                    else:
                        try:
                            func.setName(new_name, SourceType.USER_DEFINED)
                            rename_ok += 1
                        except Exception:
                            rename_fail += 1
                            continue
                    if comment:
                        try:
                            func.setComment(comment)
                            rename_cmt += 1
                        except Exception:
                            pass
                else:
                    print(f"[plan-rename] 0x{addr_int:08x} {func.getName()} -> {new_name}")

            # Step 2: optional auto direct-thunk mirror renames from core targets
            if args.auto_thunk_mirrors:
                for row in rename_rows:
                    addr_txt = (row.get("address") or "").strip()
                    core_name = (row.get("new_name") or "").strip()
                    if not addr_txt or not core_name:
                        continue
                    try:
                        core_int = parse_hex(addr_txt)
                    except Exception:
                        continue
                    core_addr = af.getAddress(f"0x{core_int:08x}")
                    for ref in rm.getReferencesTo(core_addr):
                        src = fm.getFunctionContaining(ref.getFromAddress())
                        if src is None:
                            continue
                        if src.getEntryPoint() != ref.getFromAddress():
                            continue
                        src_addr = src.getEntryPoint().getOffset() & 0xFFFFFFFF
                        if src_addr == core_int:
                            continue
                        if not single_jmp_to_target(listing, src, core_addr):
                            continue

                        old_name = src.getName()
                        if not (
                            old_name.startswith("thunk_")
                            or old_name.startswith("Cluster_")
                            or old_name.startswith("FUN_")
                        ):
                            # keep auto lane conservative
                            continue

                        desired = f"thunk_{sanitize_symbol_name(core_name)}"
                        chosen = ensure_unique_name(existing_function_names, desired, src_addr)
                        auto_thunk_rows.append(
                            {
                                "address": f"0x{src_addr:08x}",
                                "old_name": old_name,
                                "new_name": chosen,
                                "target_addr": f"0x{core_int:08x}",
                                "target_name": core_name,
                            }
                        )
                        auto_thunk_sig_map[src_addr] = core_int
                        if args.apply:
                            if old_name != chosen:
                                try:
                                    src.setName(chosen, SourceType.USER_DEFINED)
                                    existing_function_names.add(chosen)
                                except Exception:
                                    pass
                # Deduplicate by source address while preserving first choice
                seen_auto = set()
                deduped = []
                for r in auto_thunk_rows:
                    a = r["address"]
                    if a in seen_auto:
                        continue
                    seen_auto.add(a)
                    deduped.append(r)
                auto_thunk_rows = deduped

            # Step 3: explicit signatures
            for i, row in enumerate(sig_rows, start=1):
                addr_txt = (row.get("address") or "").strip()
                ret_txt = (row.get("return_type") or "").strip()
                cc_txt = (row.get("calling_convention") or "").strip()
                params_txt = row.get("params") or ""
                if not addr_txt or not ret_txt:
                    sig_fail += 1
                    print(f"[sig-row-fail] row={i} missing address/return_type")
                    continue
                try:
                    addr_int = parse_hex(addr_txt)
                    ret_dt = build_data_type(ret_txt, dtm)
                    params = parse_params(params_txt)
                except Exception as ex:
                    sig_fail += 1
                    print(f"[sig-row-fail] row={i} addr={addr_txt} err={ex}")
                    continue
                f = fm.getFunctionAt(af.getAddress(f"0x{addr_int:08x}"))
                if f is None:
                    sig_fail += 1
                    continue
                if not args.apply:
                    ptxt = ", ".join(f"{n}:{t}" for n, t in params) if params else "<none>"
                    print(
                        f"[plan-signature] 0x{addr_int:08x} {f.getName()} cc={cc_txt or '<unchanged>'} "
                        f"ret={ret_txt} params={ptxt}"
                    )
                    continue
                try:
                    old_sig = str(f.getSignature())
                    if cc_txt:
                        f.setCallingConvention(cc_txt)
                    p_objs = [
                        ParameterImpl(nm, build_data_type(tp, dtm), program, SourceType.USER_DEFINED)
                        for nm, tp in params
                    ]
                    f.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        p_objs,
                    )
                    f.setReturnType(ret_dt, SourceType.USER_DEFINED)
                    if str(f.getSignature()) == old_sig:
                        sig_skip += 1
                    else:
                        sig_ok += 1
                except Exception:
                    sig_fail += 1

            # Step 4: thunk signatures (explicit + auto)
            merged_tsig: dict[int, int] = {}
            for row in thunk_sig_rows:
                a = (row.get("address") or "").strip()
                t = (row.get("target_addr") or "").strip()
                if not a or not t:
                    continue
                try:
                    merged_tsig[parse_hex(a)] = parse_hex(t)
                except Exception:
                    continue
            for s, t in auto_thunk_sig_map.items():
                merged_tsig.setdefault(s, t)

            for src_int, dst_int in sorted(merged_tsig.items()):
                src = fm.getFunctionAt(af.getAddress(f"0x{src_int:08x}"))
                dst = fm.getFunctionAt(af.getAddress(f"0x{dst_int:08x}"))
                if src is None or dst is None:
                    tsig_fail += 1
                    continue
                if not src.getName().startswith("thunk_"):
                    tsig_skip += 1
                    continue
                if not args.apply:
                    print(
                        f"[plan-thunk-sig] 0x{src_int:08x} {src.getName()} <= "
                        f"0x{dst_int:08x} {dst.getName()}"
                    )
                    continue
                try:
                    old_sig = str(src.getSignature())
                    cc = dst.getCallingConventionName()
                    if cc:
                        src.setCallingConvention(cc)
                    params = []
                    dst_params = dst.getParameters()
                    for i in range(len(dst_params)):
                        p = dst_params[i]
                        nm = p.getName() or f"param_{i+1}"
                        params.append(
                            ParameterImpl(nm, p.getDataType(), program, SourceType.USER_DEFINED)
                        )
                    src.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        True,
                        SourceType.USER_DEFINED,
                        params,
                    )
                    src.setReturnType(dst.getReturnType(), SourceType.USER_DEFINED)
                    if str(src.getSignature()) == old_sig:
                        tsig_skip += 1
                    else:
                        tsig_ok += 1
                except Exception:
                    tsig_fail += 1
        finally:
            if tx is not None:
                program.endTransaction(tx, args.apply)

        if args.apply:
            program.save("run unresolved wave", None)

        # Step 5: post-wave artifacts in same session
        if args.auto_thunk_out_csv:
            write_dict_csv(
                Path(args.auto_thunk_out_csv),
                auto_thunk_rows,
                ["address", "old_name", "new_name", "target_addr", "target_name"],
            )
            print(f"[saved] {args.auto_thunk_out_csv} rows={len(auto_thunk_rows)}")

        if args.unresolved_main_out_csv:
            um_rows = build_unresolved_rows(
                program,
                parse_hex(args.unresolved_main_min),
                parse_hex(args.unresolved_main_max),
                args.unresolved_main_name_regex,
            )
            write_dict_csv(
                Path(args.unresolved_main_out_csv),
                um_rows,
                [
                    "address",
                    "name",
                    "namespace",
                    "instruction_count",
                    "call_insn_count",
                    "xrefs_to_count",
                    "named_caller_count",
                    "generic_caller_count",
                    "named_callee_count",
                    "generic_callee_count",
                    "named_callees",
                    "sample_callers",
                ],
            )
            print(f"[saved] {args.unresolved_main_out_csv} rows={len(um_rows)}")

        if args.strict_gate_out_csv:
            sg_rows = build_strict_gate_rows(program, args.strict_caller_regex)
            write_dict_csv(
                Path(args.strict_gate_out_csv),
                sg_rows,
                ["caller_addr", "caller_name", "generic_callee_count", "generic_callees"],
            )
            print(f"[saved] {args.strict_gate_out_csv} rows={len(sg_rows)}")

        if args.unresolved_runtime_out_csv:
            ur_rows = build_unresolved_rows(
                program,
                parse_hex(args.unresolved_runtime_min),
                parse_hex(args.unresolved_runtime_max),
                args.unresolved_runtime_name_regex,
            )
            write_dict_csv(
                Path(args.unresolved_runtime_out_csv),
                ur_rows,
                [
                    "address",
                    "name",
                    "namespace",
                    "instruction_count",
                    "call_insn_count",
                    "xrefs_to_count",
                    "named_caller_count",
                    "generic_caller_count",
                    "named_callee_count",
                    "generic_callee_count",
                    "named_callees",
                    "sample_callers",
                ],
            )
            print(f"[saved] {args.unresolved_runtime_out_csv} rows={len(ur_rows)}")

        if args.progress_out:
            progress = compute_progress(program)
            p = Path(args.progress_out)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("w", encoding="utf-8") as fh:
                for k, v in progress.items():
                    fh.write(f"{k} {v}\n")
            print(f"[saved] {args.progress_out}")
            for k, v in progress.items():
                print(f"{k} {v}")

        print(
            "[wave] "
            f"apply={args.apply} "
            f"rename_ok={rename_ok} rename_skip={rename_skip} rename_fail={rename_fail} "
            f"comments={rename_cmt} created={created} "
            f"sig_ok={sig_ok} sig_skip={sig_skip} sig_fail={sig_fail} "
            f"thunk_sig_ok={tsig_ok} thunk_sig_skip={tsig_skip} thunk_sig_fail={tsig_fail} "
            f"auto_thunks={len(auto_thunk_rows)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
