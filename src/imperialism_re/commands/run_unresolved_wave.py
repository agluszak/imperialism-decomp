#!/usr/bin/env python3
"""
Run one unresolved-promotion wave in a single pyghidra session.

This command runs:
1) core renames (and optional comments),
2) optional direct JMP-thunk mirror renames,
3) core signatures,
4) thunk signatures (explicit + auto-generated),
5) post-wave quality artifacts.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import load_csv_rows
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.typing_utils import parse_hex
from imperialism_re.core.wave_engine import WaveApplyConfig, apply_wave_rows
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


def _write_progress(path: Path, progress: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for key, value in progress.items():
            fh.write(f"{key} {value}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--renames-csv", required=True)
    ap.add_argument("--signatures-csv")
    ap.add_argument("--thunk-signatures-csv")
    ap.add_argument("--auto-thunk-mirrors", action="store_true")
    ap.add_argument("--auto-thunk-out-csv")
    ap.add_argument("--create-missing", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=default_project_root())

    ap.add_argument("--unresolved-main-min", default="0x00400000")
    ap.add_argument("--unresolved-main-max", default="0x006FFFFF")
    ap.add_argument("--unresolved-main-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--unresolved-main-out-csv")

    ap.add_argument(
        "--strict-caller-regex",
        default=r"^(?!FUN_|thunk_|Cluster_|WrapperFor_Cluster_).+",
    )
    ap.add_argument("--strict-gate-out-csv")

    ap.add_argument("--unresolved-runtime-min", default="0x00600000")
    ap.add_argument("--unresolved-runtime-max", default="0x0062FFFF")
    ap.add_argument("--unresolved-runtime-name-regex", default=r"^(FUN_|thunk_FUN_|Cluster_)")
    ap.add_argument("--unresolved-runtime-out-csv")

    ap.add_argument("--progress-out")
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    renames_csv = Path(args.renames_csv)
    if not renames_csv.is_absolute():
        renames_csv = root / renames_csv
    if not renames_csv.exists():
        print(f"missing renames csv: {renames_csv}")
        return 1

    sig_csv = Path(args.signatures_csv) if args.signatures_csv else None
    if sig_csv is not None and not sig_csv.is_absolute():
        sig_csv = root / sig_csv
    if sig_csv is not None and not sig_csv.exists():
        print(f"missing signatures csv: {sig_csv}")
        return 1

    thunk_sig_csv = Path(args.thunk_signatures_csv) if args.thunk_signatures_csv else None
    if thunk_sig_csv is not None and not thunk_sig_csv.is_absolute():
        thunk_sig_csv = root / thunk_sig_csv
    if thunk_sig_csv is not None and not thunk_sig_csv.exists():
        print(f"missing thunk signatures csv: {thunk_sig_csv}")
        return 1

    rename_rows = load_csv_rows(renames_csv)
    sig_rows = load_csv_rows(sig_csv) if sig_csv else []
    thunk_sig_rows = load_csv_rows(thunk_sig_csv) if thunk_sig_csv else []

    with open_program(root) as program:
        result = apply_wave_rows(
            program,
            rename_rows=rename_rows,
            sig_rows=sig_rows,
            thunk_sig_rows=thunk_sig_rows,
            config=WaveApplyConfig(
                apply=args.apply,
                create_missing=args.create_missing,
                auto_thunk_mirrors=args.auto_thunk_mirrors,
                transaction_label="Run unresolved wave",
                save_message="run unresolved wave",
            ),
        )

        if args.auto_thunk_out_csv:
            write_dict_csv(
                Path(args.auto_thunk_out_csv),
                result.auto_thunk_rows,
                ["address", "old_name", "new_name", "target_addr", "target_name"],
            )
            print(f"[saved] {args.auto_thunk_out_csv} rows={len(result.auto_thunk_rows)}")

        if args.unresolved_main_out_csv:
            rows = build_unresolved_rows(
                program,
                parse_hex(args.unresolved_main_min),
                parse_hex(args.unresolved_main_max),
                args.unresolved_main_name_regex,
            )
            write_dict_csv(Path(args.unresolved_main_out_csv), rows, UNRESOLVED_FIELDS)
            print(f"[saved] {args.unresolved_main_out_csv} rows={len(rows)}")

        if args.strict_gate_out_csv:
            rows = build_strict_gate_rows(program, args.strict_caller_regex)
            write_dict_csv(
                Path(args.strict_gate_out_csv),
                rows,
                ["caller_addr", "caller_name", "generic_callee_count", "generic_callees"],
            )
            print(f"[saved] {args.strict_gate_out_csv} rows={len(rows)}")

        if args.unresolved_runtime_out_csv:
            rows = build_unresolved_rows(
                program,
                parse_hex(args.unresolved_runtime_min),
                parse_hex(args.unresolved_runtime_max),
                args.unresolved_runtime_name_regex,
            )
            write_dict_csv(Path(args.unresolved_runtime_out_csv), rows, UNRESOLVED_FIELDS)
            print(f"[saved] {args.unresolved_runtime_out_csv} rows={len(rows)}")

        if args.progress_out:
            progress = compute_progress(program)
            _write_progress(Path(args.progress_out), progress)
            print(f"[saved] {args.progress_out}")
            for key, value in progress.items():
                print(f"{key} {value}")

    print(
        "[wave] "
        f"apply={args.apply} "
        f"rename_ok={result.rename_ok} rename_skip={result.rename_skip} rename_fail={result.rename_fail} "
        f"comments={result.rename_comments} created={result.created_functions} "
        f"sig_ok={result.sig_ok} sig_skip={result.sig_skip} sig_fail={result.sig_fail} "
        f"thunk_sig_ok={result.thunk_sig_ok} thunk_sig_skip={result.thunk_sig_skip} "
        f"thunk_sig_fail={result.thunk_sig_fail} auto_thunks={len(result.auto_thunk_rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
