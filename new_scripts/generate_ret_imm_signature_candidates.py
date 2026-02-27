#!/usr/bin/env python3
"""
Generate callback/signature candidates from functions ending with RET imm.

The script scans functions, finds those whose last instruction is RET <imm>,
and emits:
  1) a candidate report CSV (rich context)
  2) an optional signatures CSV in apply_signatures_from_csv.py format

Usage:
  .venv/bin/python new_scripts/generate_ret_imm_signature_candidates.py \
    --ret-imm 0x14 \
    --name-regex "Handle|Dialog|Command|Callback|Control|Button|Mouse|Scroll|Key" \
    --out-csv tmp_decomp/ret14_candidates.csv \
    --out-signatures-csv tmp_decomp/ret14_signatures.csv
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


def parse_int(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def is_generic(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def read_last_instruction(listing, body):
    it = listing.getInstructions(body, True)
    last = None
    while it.hasNext():
        last = it.next()
    return last


def ret_imm_of_instruction(ins) -> int | None:
    if ins is None:
        return None
    if str(ins.getMnemonicString()).upper() != "RET":
        return None
    if ins.getNumOperands() < 1:
        return 0
    sc = ins.getScalar(0)
    if sc is None:
        return None
    try:
        return int(sc.getUnsignedValue())
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--ret-imm",
        default="0x14",
        help="RET immediate value to match (hex or dec), e.g. 0x14",
    )
    ap.add_argument(
        "--name-regex",
        default="Handle|Dialog|Command|Callback|Control|Button|Mouse|Scroll|Key",
        help="Regex filter applied to function names",
    )
    ap.add_argument(
        "--exclude-generic-callers",
        action="store_true",
        help="Exclude generic names (FUN_/Cluster_/WrapperFor_Cluster_)",
    )
    ap.add_argument(
        "--only-zero-param-signatures",
        action="store_true",
        help="Only emit functions currently decompiled as zero formal params",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/ret_imm_signature_candidates.csv",
        help="Candidate report CSV path",
    )
    ap.add_argument(
        "--out-signatures-csv",
        default="",
        help="Optional signatures CSV path for apply_signatures_from_csv.py",
    )
    ap.add_argument(
        "--min-score",
        type=int,
        default=6,
        help="Minimum confidence score for safe application/output filtering",
    )
    ap.add_argument(
        "--max-safe-instruction-count",
        type=int,
        default=220,
        help="Do not auto-apply signatures for very large functions",
    )
    ap.add_argument(
        "--min-safe-caller-count",
        type=int,
        default=1,
        help="Minimum caller count required for auto-apply",
    )
    ap.add_argument(
        "--safe-denylist-regex",
        default=r"^(WrapperFor_|thunk_)",
        help="Regex of function names to skip during --apply-safe",
    )
    ap.add_argument(
        "--apply-safe",
        action="store_true",
        help="Apply signatures directly for high-confidence candidates only",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    target_ret_imm = parse_int(args.ret_imm)
    name_re = re.compile(args.name_regex) if args.name_regex else None
    deny_re = re.compile(args.safe_denylist_regex) if args.safe_denylist_regex else None
    out_csv = Path(args.out_csv)
    out_sig_csv = Path(args.out_signatures_csv) if args.out_signatures_csv else None

    root = Path(args.project_root).resolve()
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows: list[dict[str, str]] = []
    sig_rows: list[dict[str, str]] = []
    safe_rows: list[dict[str, str]] = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.data import IntegerDataType, VoidDataType
        from ghidra.program.model.listing import Function, ParameterImpl
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            name = f.getName()
            if name_re and not name_re.search(name):
                continue
            if args.exclude_generic_callers and is_generic(name):
                continue

            last = read_last_instruction(listing, f.getBody())
            imm = ret_imm_of_instruction(last)
            if imm is None or imm != target_ret_imm:
                continue

            param_count = imm // 4 if imm >= 0 and (imm % 4 == 0) else -1
            current_sig = str(f.getSignature())
            has_zero_params = current_sig.endswith("(void)")
            if args.only_zero_param_signatures and not has_zero_params:
                continue

            # Feature extraction for confidence scoring.
            insns = []
            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                insns.append(ins_it.next())
            ins_count = len(insns)

            ecx_use_count = 0
            for ins in insns:
                txt = str(ins).upper()
                if "ECX" in txt:
                    ecx_use_count += 1

            refs = rm.getReferencesTo(af.getAddress(str(f.getEntryPoint())))
            caller_total = 0
            push_match = 0
            ecx_setup = 0
            for ref in refs:
                from_addr = ref.getFromAddress()
                call_ins = listing.getInstructionAt(from_addr)
                if call_ins is None:
                    continue
                if str(call_ins.getMnemonicString()).upper() != "CALL":
                    continue
                caller_total += 1
                # inspect up to 8 instructions backward.
                n_push = 0
                has_ecx_setup = False
                back = call_ins.getPrevious()
                steps = 0
                while back is not None and steps < 8:
                    m = str(back.getMnemonicString()).upper()
                    t = str(back).upper()
                    if m == "PUSH":
                        n_push += 1
                    if m in ("MOV", "LEA", "XOR") and "ECX" in t:
                        has_ecx_setup = True
                    if m in ("CALL", "RET", "JMP"):
                        break
                    back = back.getPrevious()
                    steps += 1
                if param_count >= 0 and n_push == param_count:
                    push_match += 1
                if has_ecx_setup:
                    ecx_setup += 1

            push_match_ratio = (push_match / caller_total) if caller_total else 0.0
            ecx_setup_ratio = (ecx_setup / caller_total) if caller_total else 0.0

            # Confidence score.
            score = 0
            if param_count > 0 and has_zero_params:
                score += 2
            if caller_total > 0:
                score += 1
            if caller_total >= 2:
                score += 1
            if push_match_ratio >= 0.60:
                score += 2
            elif push_match_ratio >= 0.30:
                score += 1
            if ecx_setup_ratio >= 0.60:
                score += 2
            elif ecx_setup_ratio >= 0.30:
                score += 1
            if ecx_use_count >= 3:
                score += 1
            if ins_count <= 120:
                score += 1

            suggested_cc = "__thiscall" if (ecx_setup_ratio >= 0.60 or ecx_use_count >= 6) else "__stdcall"
            entry = str(f.getEntryPoint())
            row = {
                "address": entry if entry.startswith("0x") else f"0x{entry}",
                "function_name": name,
                "ret_imm": str(imm),
                "param_count_from_ret": str(param_count),
                "instruction_count": str(ins_count),
                "ecx_use_count": str(ecx_use_count),
                "caller_count": str(caller_total),
                "push_match_count": str(push_match),
                "push_match_ratio": f"{push_match_ratio:.2f}",
                "ecx_setup_count": str(ecx_setup),
                "ecx_setup_ratio": f"{ecx_setup_ratio:.2f}",
                "confidence_score": str(score),
                "current_signature": current_sig,
                "suggested_calling_convention": suggested_cc,
                "suggested_return_type": "void",
                "suggested_params": ";".join(f"arg{i+1}:int" for i in range(max(param_count, 0))),
            }
            rows.append(row)

            if out_sig_csv is not None and param_count >= 0:
                sig_rows.append(
                    {
                        "address": row["address"],
                        "calling_convention": suggested_cc,
                        "return_type": "void",
                        "params": row["suggested_params"],
                    }
                )

            safe_ok = (
                score >= args.min_score
                and param_count >= 0
                and ins_count <= args.max_safe_instruction_count
                and caller_total >= args.min_safe_caller_count
                and push_match_ratio >= 0.30
            )
            if safe_ok and deny_re and deny_re.search(name):
                safe_ok = False
            if safe_ok:
                safe_rows.append(row)

        if args.apply_safe and safe_rows:
            int_t = IntegerDataType.dataType
            void_t = VoidDataType.dataType
            tx = program.startTransaction("Apply safe ret-imm signatures")
            ok = 0
            fail = 0
            try:
                for r in safe_rows:
                    addr = af.getAddress(r["address"].lower())
                    f = fm.getFunctionAt(addr)
                    if f is None:
                        fail += 1
                        continue
                    param_count = int(r["param_count_from_ret"])
                    if param_count < 0:
                        fail += 1
                        continue
                    try:
                        f.setCallingConvention(r["suggested_calling_convention"])
                        p_objs = [
                            ParameterImpl(f"arg{i+1}", int_t, program, SourceType.USER_DEFINED)
                            for i in range(param_count)
                        ]
                        f.replaceParameters(
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                            True,
                            SourceType.USER_DEFINED,
                            p_objs,
                        )
                        f.setReturnType(void_t, SourceType.USER_DEFINED)
                        ok += 1
                    except Exception:
                        fail += 1
            finally:
                program.endTransaction(tx, True)
            program.save("apply safe ret-imm signatures", None)
            print(f"[apply-safe] ok={ok} fail={fail} min_score={args.min_score}")

    rows.sort(key=lambda r: (r["function_name"], r["address"]))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "address",
                "function_name",
                "ret_imm",
                "param_count_from_ret",
                "instruction_count",
                "ecx_use_count",
                "caller_count",
                "push_match_count",
                "push_match_ratio",
                "ecx_setup_count",
                "ecx_setup_ratio",
                "confidence_score",
                "current_signature",
                "suggested_calling_convention",
                "suggested_return_type",
                "suggested_params",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    if out_sig_csv is not None:
        out_sig_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_sig_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(
                fh,
                fieldnames=["address", "calling_convention", "return_type", "params"],
            )
            w.writeheader()
            w.writerows(sig_rows)

    print(
        f"[saved] candidates={len(rows)} ret_imm={target_ret_imm} out={out_csv}"
    )
    print(
        f"[saved] safe_candidates={len(safe_rows)} min_score={args.min_score} "
        f"max_safe_instruction_count={args.max_safe_instruction_count} "
        f"min_safe_caller_count={args.min_safe_caller_count}"
    )
    if out_sig_csv is not None:
        print(f"[saved] signatures={len(sig_rows)} out={out_sig_csv}")
    for r in rows[:120]:
        print(
            f"{r['address']},{r['function_name']},ret={r['ret_imm']},"
            f"params={r['param_count_from_ret']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
