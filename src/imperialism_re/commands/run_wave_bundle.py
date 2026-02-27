#!/usr/bin/env python3
"""
Run one standardized RE wave bundle in a single pyghidra session.

Flow:
1) pre snapshots (unresolved main, strict gate, runtime gate, progress)
2) apply wave (renames, signatures, thunk signature propagation)
3) post snapshots (same artifacts)
4) write one compact summary file
"""

from __future__ import annotations

import argparse
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import load_csv_rows
from imperialism_re.core.datatypes import (
    DEFAULT_CANONICAL_PROJECT_ROOT,
    DEFAULT_LEGACY_PROJECT_ROOTS,
    collect_root_policy_violations,
)
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex
from imperialism_re.core.wave_engine import WaveApplyConfig, WaveApplyResult, apply_wave_rows
from imperialism_re.core.wave_shared import (
    build_strict_gate_rows,
    build_unresolved_rows,
    compute_progress,
    write_dict_csv,
)

UNRESOLVED_FIELDS = [
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
]


def write_progress(path: Path, progress: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for key, value in progress.items():
            fh.write(f"{key} {value}\n")


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
    ap.add_argument("--project-root", default=default_project_root())
    ap.add_argument(
        "--strict-caller-regex",
        default=r"^(?!FUN_|thunk_FUN_|thunk_|CreateSingleJmpThunk_)(?!Cluster_)(?!WrapperFor_Cluster_).*",
    )
    ap.add_argument("--unresolved-main-min", default="0x00400000")
    ap.add_argument("--unresolved-main-max", default="0x006fffff")
    ap.add_argument("--unresolved-main-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--unresolved-runtime-min", default="0x00600000")
    ap.add_argument("--unresolved-runtime-max", default="0x0062ffff")
    ap.add_argument("--unresolved-runtime-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    out_dir = root / "tmp_decomp"
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = args.batch_tag

    renames_csv = Path(args.renames_csv)
    if not renames_csv.is_absolute():
        renames_csv = root / renames_csv
    if not renames_csv.exists():
        print(f"[error] missing renames csv: {renames_csv}")
        return 1

    sig_csv = Path(args.signatures_csv) if args.signatures_csv else None
    if sig_csv is not None and not sig_csv.is_absolute():
        sig_csv = root / sig_csv
    if sig_csv is not None and not sig_csv.exists():
        print(f"[error] missing signatures csv: {sig_csv}")
        return 1

    thunk_sig_csv = Path(args.thunk_signatures_csv) if args.thunk_signatures_csv else None
    if thunk_sig_csv is not None and not thunk_sig_csv.is_absolute():
        thunk_sig_csv = root / thunk_sig_csv
    if thunk_sig_csv is not None and not thunk_sig_csv.exists():
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
    pre_dtype_policy_csv = out_dir / f"{tag}_datatype_root_policy_pre.csv"
    post_dtype_policy_csv = out_dir / f"{tag}_datatype_root_policy_post.csv"

    pre_um_rows = []
    pre_sg_rows = []
    pre_ur_rows = []
    pre_progress: dict[str, int] = {}
    post_um_rows = []
    post_sg_rows = []
    post_ur_rows = []
    post_progress: dict[str, int] = {}
    pre_policy_rows: list[dict[str, str]] = []
    post_policy_rows: list[dict[str, str]] = []
    aborted_reason = ""
    return_code = 0
    result = WaveApplyResult(
        rename_ok=0,
        rename_skip=0,
        rename_fail=0,
        rename_comments=0,
        created_functions=0,
        sig_ok=0,
        sig_skip=0,
        sig_fail=0,
        thunk_sig_ok=0,
        thunk_sig_skip=0,
        thunk_sig_fail=0,
        auto_thunk_rows=[],
    )

    with open_program(root) as program:
        pre_policy_rows = collect_root_policy_violations(
            program.getDataTypeManager(),
            canonical_root=DEFAULT_CANONICAL_PROJECT_ROOT,
            forbidden_roots=DEFAULT_LEGACY_PROJECT_ROOTS,
        )
        if pre_policy_rows:
            write_dict_csv(
                pre_dtype_policy_csv,
                pre_policy_rows,
                ["full_path", "category_path", "forbidden_root", "canonical_root"],
            )
            print(
                f"[error] datatype-root-policy-pre violations={len(pre_policy_rows)} csv={pre_dtype_policy_csv}"
            )
            for row in pre_policy_rows[:40]:
                print(f"  {row['full_path']} (root={row['forbidden_root']})")
            if len(pre_policy_rows) > 40:
                print(f"  ... ({len(pre_policy_rows) - 40} more)")
            aborted_reason = "pre_datatype_root_policy_failed"
            return_code = 2
        else:
            if args.emit_detail_artifacts:
                write_dict_csv(
                    pre_dtype_policy_csv,
                    pre_policy_rows,
                    ["full_path", "category_path", "forbidden_root", "canonical_root"],
                )
                print(f"[saved] {pre_dtype_policy_csv} rows={len(pre_policy_rows)}")

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
                write_dict_csv(pre_main_csv, pre_um_rows, UNRESOLVED_FIELDS)
                write_dict_csv(
                    pre_strict_csv,
                    pre_sg_rows,
                    ["caller_addr", "caller_name", "generic_callee_count", "generic_callees"],
                )
                write_dict_csv(pre_runtime_csv, pre_ur_rows, UNRESOLVED_FIELDS)
                write_progress(pre_progress_txt, pre_progress)
                print(f"[saved] {pre_main_csv} rows={len(pre_um_rows)}")
                print(f"[saved] {pre_strict_csv} rows={len(pre_sg_rows)}")
                print(f"[saved] {pre_runtime_csv} rows={len(pre_ur_rows)}")
                print(f"[saved] {pre_progress_txt}")

            result = apply_wave_rows(
                program,
                rename_rows=rename_rows,
                sig_rows=sig_rows,
                thunk_sig_rows=thunk_sig_rows,
                config=WaveApplyConfig(
                    apply=args.apply,
                    create_missing=args.create_missing,
                    auto_thunk_mirrors=args.auto_thunk_mirrors,
                    transaction_label="Run wave bundle",
                    save_message="run wave bundle",
                ),
            )

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
            post_policy_rows = collect_root_policy_violations(
                program.getDataTypeManager(),
                canonical_root=DEFAULT_CANONICAL_PROJECT_ROOT,
                forbidden_roots=DEFAULT_LEGACY_PROJECT_ROOTS,
            )
            if post_policy_rows:
                write_dict_csv(
                    post_dtype_policy_csv,
                    post_policy_rows,
                    ["full_path", "category_path", "forbidden_root", "canonical_root"],
                )
                print(
                    f"[error] datatype-root-policy-post violations={len(post_policy_rows)} csv={post_dtype_policy_csv}"
                )
                for row in post_policy_rows[:40]:
                    print(f"  {row['full_path']} (root={row['forbidden_root']})")
                if len(post_policy_rows) > 40:
                    print(f"  ... ({len(post_policy_rows) - 40} more)")
                return_code = 2
            elif args.emit_detail_artifacts:
                write_dict_csv(
                    post_dtype_policy_csv,
                    post_policy_rows,
                    ["full_path", "category_path", "forbidden_root", "canonical_root"],
                )
                print(f"[saved] {post_dtype_policy_csv} rows={len(post_policy_rows)}")

            if args.emit_detail_artifacts:
                write_dict_csv(post_main_csv, post_um_rows, UNRESOLVED_FIELDS)
                write_dict_csv(
                    post_strict_csv,
                    post_sg_rows,
                    ["caller_addr", "caller_name", "generic_callee_count", "generic_callees"],
                )
                write_dict_csv(post_runtime_csv, post_ur_rows, UNRESOLVED_FIELDS)
                write_progress(post_progress_txt, post_progress)
                if args.auto_thunk_mirrors:
                    write_dict_csv(
                        auto_thunks_csv,
                        result.auto_thunk_rows,
                        ["address", "old_name", "new_name", "target_addr", "target_name"],
                    )
                print(f"[saved] {post_main_csv} rows={len(post_um_rows)}")
                print(f"[saved] {post_strict_csv} rows={len(post_sg_rows)}")
                print(f"[saved] {post_runtime_csv} rows={len(post_ur_rows)}")
                print(f"[saved] {post_progress_txt}")
                if args.auto_thunk_mirrors:
                    print(f"[saved] {auto_thunks_csv} rows={len(result.auto_thunk_rows)}")

    summary_lines = [
        f"batch_tag={tag}",
        f"apply={int(args.apply)}",
        f"pre_unresolved_rows={len(pre_um_rows)}",
        f"post_unresolved_rows={len(post_um_rows)}",
        f"pre_strict_rows={len(pre_sg_rows)}",
        f"post_strict_rows={len(post_sg_rows)}",
        f"pre_runtime_rows={len(pre_ur_rows)}",
        f"post_runtime_rows={len(post_ur_rows)}",
        f"pre_datatype_root_policy_rows={len(pre_policy_rows)}",
        f"post_datatype_root_policy_rows={len(post_policy_rows)}",
        f"pre_default_fun_or_thunk_fun={pre_progress.get('default_fun_or_thunk_fun', '')}",
        f"post_default_fun_or_thunk_fun={post_progress.get('default_fun_or_thunk_fun', '')}",
        f"rename_ok={result.rename_ok}",
        f"rename_skip={result.rename_skip}",
        f"rename_fail={result.rename_fail}",
        f"sig_ok={result.sig_ok}",
        f"sig_skip={result.sig_skip}",
        f"sig_fail={result.sig_fail}",
        f"thunk_sig_ok={result.thunk_sig_ok}",
        f"thunk_sig_skip={result.thunk_sig_skip}",
        f"thunk_sig_fail={result.thunk_sig_fail}",
        f"auto_thunks={len(result.auto_thunk_rows)}",
        f"emit_detail_artifacts={int(args.emit_detail_artifacts)}",
        f"aborted_reason={aborted_reason}",
        f"return_code={return_code}",
    ]
    summary_txt.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(f"[saved] {summary_txt}")
    print(
        "[wave-bundle] "
        f"apply={args.apply} "
        f"rename_ok={result.rename_ok} rename_skip={result.rename_skip} rename_fail={result.rename_fail} "
        f"sig_ok={result.sig_ok} sig_skip={result.sig_skip} sig_fail={result.sig_fail} "
        f"thunk_sig_ok={result.thunk_sig_ok} thunk_sig_skip={result.thunk_sig_skip} "
        f"thunk_sig_fail={result.thunk_sig_fail} auto_thunks={len(result.auto_thunk_rows)} "
        f"dtype_policy_pre={len(pre_policy_rows)} dtype_policy_post={len(post_policy_rows)} "
        f"return_code={return_code}"
    )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
