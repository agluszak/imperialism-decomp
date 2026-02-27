#!/usr/bin/env python3
"""
Run one standardized RE wave bundle in a single pyghidra session.

Flow:
1) pre snapshots (unresolved main, strict gate, runtime gate, progress)
2) apply wave (renames, signatures, thunk signature propagation)
3) post snapshots (same artifacts)
4) write one compact summary file

Usage:
  .venv/bin/python new_scripts/run_wave_bundle.py \
    --batch-tag batch450 \
    --renames-csv tmp_decomp/batch450_wave_renames.csv \
    --signatures-csv tmp_decomp/batch450_wave_signatures.csv \
    --auto-thunk-mirrors \
    --apply
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pyghidra

from run_unresolved_wave import (
    GHIDRA_DIR,
    PROGRAM_PATH,
    build_data_type,
    build_strict_gate_rows,
    build_unresolved_rows,
    compute_progress,
    ensure_unique_name,
    load_csv_rows,
    open_project_with_lock_cleanup,
    parse_hex,
    parse_params,
    sanitize_symbol_name,
    single_jmp_to_target,
    write_dict_csv,
)


def write_progress(path: Path, progress: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for k, v in progress.items():
            fh.write(f"{k} {v}\n")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-tag", required=True, help="Prefix for tmp_decomp artifacts")
    ap.add_argument("--renames-csv", required=True)
    ap.add_argument("--signatures-csv")
    ap.add_argument("--thunk-signatures-csv")
    ap.add_argument("--auto-thunk-mirrors", action="store_true")
    ap.add_argument("--create-missing", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument(
        "--emit-detail-artifacts",
        action="store_true",
        help="Write detailed pre/post CSV artifacts (default: summary-only)",
    )
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--strict-caller-regex", default=r"^(?!FUN_|thunk_FUN_|thunk_|CreateSingleJmpThunk_)(?!Cluster_)(?!WrapperFor_Cluster_).*")
    ap.add_argument("--unresolved-main-min", default="0x00400000")
    ap.add_argument("--unresolved-main-max", default="0x006fffff")
    ap.add_argument("--unresolved-main-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--unresolved-runtime-min", default="0x00600000")
    ap.add_argument("--unresolved-runtime-max", default="0x0062ffff")
    ap.add_argument("--unresolved-runtime-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_dir = root / "tmp_decomp"
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = args.batch_tag

    renames_csv = Path(args.renames_csv)
    if not renames_csv.is_absolute():
        renames_csv = root / renames_csv
    if not renames_csv.exists():
        print(f"[error] missing renames csv: {renames_csv}")
        return 1

    sig_csv = None
    if args.signatures_csv:
        sig_csv = Path(args.signatures_csv)
        if not sig_csv.is_absolute():
            sig_csv = root / sig_csv
        if not sig_csv.exists():
            print(f"[error] missing signatures csv: {sig_csv}")
            return 1

    thunk_sig_csv = None
    if args.thunk_signatures_csv:
        thunk_sig_csv = Path(args.thunk_signatures_csv)
        if not thunk_sig_csv.is_absolute():
            thunk_sig_csv = root / thunk_sig_csv
        if not thunk_sig_csv.exists():
            print(f"[error] missing thunk signatures csv: {thunk_sig_csv}")
            return 1

    rename_rows = load_csv_rows(renames_csv)
    sig_rows = load_csv_rows(sig_csv) if sig_csv else []
    thunk_sig_rows = load_csv_rows(thunk_sig_csv) if thunk_sig_csv else []

    pre_main_csv = out_dir / f"{tag}_unresolved_0040_006f_pre.csv"
    pre_strict_csv = out_dir / f"{tag}_named_callers_with_generic_callees_superlane_strict_pre.csv"
    pre_runtime_csv = out_dir / f"{tag}_unresolved_0060_0062_runtime_bridge_pre.csv"
    pre_progress_txt = out_dir / f"{tag}_progress_pre.txt"

    post_main_csv = out_dir / f"{tag}_unresolved_0040_006f_post.csv"
    post_strict_csv = out_dir / f"{tag}_named_callers_with_generic_callees_superlane_strict_post.csv"
    post_runtime_csv = out_dir / f"{tag}_unresolved_0060_0062_runtime_bridge_post.csv"
    post_progress_txt = out_dir / f"{tag}_progress_post.txt"
    auto_thunks_csv = out_dir / f"{tag}_auto_thunk_mirrors.csv"
    summary_txt = out_dir / f"{tag}_bundle_summary.txt"

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
        monitor = ConsoleTaskMonitor()

        # Pre snapshots
        pre_um_rows = build_unresolved_rows(
            program,
            parse_hex(args.unresolved_main_min),
            parse_hex(args.unresolved_main_max),
            args.unresolved_main_name_regex,
        )
        pre_sg_rows = build_strict_gate_rows(program, args.strict_caller_regex)
        pre_ur_rows = build_unresolved_rows(
            program,
            parse_hex(args.unresolved_runtime_min),
            parse_hex(args.unresolved_runtime_max),
            args.unresolved_runtime_name_regex,
        )
        pre_progress = compute_progress(program)
        if args.emit_detail_artifacts:
            write_dict_csv(
                pre_main_csv,
                pre_um_rows,
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
            write_dict_csv(
                pre_strict_csv,
                pre_sg_rows,
                ["caller_addr", "caller_name", "generic_callee_count", "generic_callees"],
            )
            write_dict_csv(
                pre_runtime_csv,
                pre_ur_rows,
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
            write_progress(pre_progress_txt, pre_progress)
            print(f"[saved] {pre_main_csv} rows={len(pre_um_rows)}")
            print(f"[saved] {pre_strict_csv} rows={len(pre_sg_rows)}")
            print(f"[saved] {pre_runtime_csv} rows={len(pre_ur_rows)}")
            print(f"[saved] {pre_progress_txt}")

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
            tx = program.startTransaction("Run wave bundle")
        try:
            # Core renames
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
                        CreateFunctionCmd(None, addr, None, SourceType.USER_DEFINED).applyTo(program, monitor)
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

            # Optional auto thunk mirrors
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
                        if args.apply and old_name != chosen:
                            try:
                                src.setName(chosen, SourceType.USER_DEFINED)
                                existing_function_names.add(chosen)
                            except Exception:
                                pass

                seen_auto = set()
                deduped = []
                for r in auto_thunk_rows:
                    if r["address"] in seen_auto:
                        continue
                    seen_auto.add(r["address"])
                    deduped.append(r)
                auto_thunk_rows = deduped

            # Signatures
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
                    ret_dt = build_data_type(ret_txt)
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
                    print(f"[plan-signature] 0x{addr_int:08x} {f.getName()} cc={cc_txt or '<unchanged>'} ret={ret_txt} params={ptxt}")
                    continue
                try:
                    old_sig = str(f.getSignature())
                    if cc_txt:
                        f.setCallingConvention(cc_txt)
                    p_objs = [ParameterImpl(nm, build_data_type(tp), program, SourceType.USER_DEFINED) for nm, tp in params]
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

            # Thunk signatures
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
                    print(f"[plan-thunk-sig] 0x{src_int:08x} {src.getName()} <= 0x{dst_int:08x} {dst.getName()}")
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
                        params.append(ParameterImpl(nm, p.getDataType(), program, SourceType.USER_DEFINED))
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
            program.save("run wave bundle", None)

        # Post snapshots
        post_um_rows = build_unresolved_rows(
            program,
            parse_hex(args.unresolved_main_min),
            parse_hex(args.unresolved_main_max),
            args.unresolved_main_name_regex,
        )
        post_sg_rows = build_strict_gate_rows(program, args.strict_caller_regex)
        post_ur_rows = build_unresolved_rows(
            program,
            parse_hex(args.unresolved_runtime_min),
            parse_hex(args.unresolved_runtime_max),
            args.unresolved_runtime_name_regex,
        )
        post_progress = compute_progress(program)
        if args.emit_detail_artifacts:
            write_dict_csv(
                post_main_csv,
                post_um_rows,
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
            write_dict_csv(
                post_strict_csv,
                post_sg_rows,
                ["caller_addr", "caller_name", "generic_callee_count", "generic_callees"],
            )
            write_dict_csv(
                post_runtime_csv,
                post_ur_rows,
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
            write_progress(post_progress_txt, post_progress)
            if args.auto_thunk_mirrors:
                write_dict_csv(
                    auto_thunks_csv,
                    auto_thunk_rows,
                    ["address", "old_name", "new_name", "target_addr", "target_name"],
                )
            print(f"[saved] {post_main_csv} rows={len(post_um_rows)}")
            print(f"[saved] {post_strict_csv} rows={len(post_sg_rows)}")
            print(f"[saved] {post_runtime_csv} rows={len(post_ur_rows)}")
            print(f"[saved] {post_progress_txt}")
            if args.auto_thunk_mirrors:
                print(f"[saved] {auto_thunks_csv} rows={len(auto_thunk_rows)}")

        summary_lines = [
            f"batch_tag={tag}",
            f"apply={int(args.apply)}",
            f"pre_unresolved_rows={len(pre_um_rows)}",
            f"post_unresolved_rows={len(post_um_rows)}",
            f"pre_strict_rows={len(pre_sg_rows)}",
            f"post_strict_rows={len(post_sg_rows)}",
            f"pre_runtime_rows={len(pre_ur_rows)}",
            f"post_runtime_rows={len(post_ur_rows)}",
            f"pre_default_fun_or_thunk_fun={pre_progress.get('default_fun_or_thunk_fun','')}",
            f"post_default_fun_or_thunk_fun={post_progress.get('default_fun_or_thunk_fun','')}",
            f"rename_ok={rename_ok}",
            f"rename_skip={rename_skip}",
            f"rename_fail={rename_fail}",
            f"sig_ok={sig_ok}",
            f"sig_skip={sig_skip}",
            f"sig_fail={sig_fail}",
            f"thunk_sig_ok={tsig_ok}",
            f"thunk_sig_skip={tsig_skip}",
            f"thunk_sig_fail={tsig_fail}",
            f"auto_thunks={len(auto_thunk_rows)}",
            f"emit_detail_artifacts={int(args.emit_detail_artifacts)}",
        ]
        summary_txt.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
        print(f"[saved] {summary_txt}")
        print(
            "[wave-bundle] "
            f"apply={args.apply} rename_ok={rename_ok} rename_skip={rename_skip} rename_fail={rename_fail} "
            f"sig_ok={sig_ok} sig_skip={sig_skip} sig_fail={sig_fail} "
            f"thunk_sig_ok={tsig_ok} thunk_sig_skip={tsig_skip} thunk_sig_fail={tsig_fail} "
            f"auto_thunks={len(auto_thunk_rows)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
