#!/usr/bin/env python3
"""
Build a global command-tag dispatch matrix and high-confidence handler rename candidates.

Inputs:
  detail CSV from extract_control_tag_usage.py

Outputs:
  1) matrix CSV: one row per function with tag + heuristic evidence
  2) candidate rename CSV: address,new_name,comment for apply_function_renames_csv.py

Usage:
  .venv/bin/python new_scripts/generate_command_tag_dispatch_matrix.py \
    --detail-csv tmp_decomp/batch204_control_tags_detail.csv \
    --out-matrix-csv tmp_decomp/command_tag_dispatch_matrix.csv \
    --out-candidate-csv tmp_decomp/command_tag_handler_rename_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"


TAG_NAME_MAP = {
    "yako": "Okay",
    "lcnc": "Cncl",
    "cnac": "Canc",
    "txen": "Next",
    "verp": "Prev",
    "kcab": "Back",
    "ofni": "Info",
    "pleh": "Help",
    "tfel": "Left",
    "thgr": "Rght",
    "ecca": "Acce",
    "ejer": "Reje",
    "tiaw": "Wait",
    "enod": "Done",
    "dart": "Trad",
    "nart": "Tran",
    "aert": "Trea",
    "kcip": "Pick",
    "galf": "Flag",
    "nalp": "Plan",
    "bolg": "Glob",
    "taoc": "Coat",
    "dnes": "Send",
    "daol": "Load",
    "tiuq": "Quit",
    "loot": "Tool",
    "sruc": "Curs",
}

TAG_PRIORITY = [
    "yako",
    "lcnc",
    "cnac",
    "txen",
    "verp",
    "kcab",
    "ofni",
    "pleh",
    "tfel",
    "thgr",
    "ecca",
    "ejer",
    "tiaw",
    "enod",
    "dart",
    "nart",
    "aert",
    "kcip",
    "galf",
    "nalp",
    "bolg",
    "taoc",
    "dnes",
    "daol",
    "tiuq",
]

EVENT_RE = re.compile(
    r"(eventCode|in_stack_00000004|modeFlag|param_2)\s*==|switch\s*\(|==\s*0x[0-9a-fA-F]+"
)
LOOKUP_RE = re.compile(r"\+\s*0x94\)|\+\s*0x1ac\)|\+\s*0x1d0\)|\+\s*0x1d4\)")
HANDLER_NAME_RE = re.compile(r"^(Handle|Run|Dispatch|Process|Configure)")
INIT_NAME_RE = re.compile(r"^(Initialize|Construct|Build|Create)")


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


def sanitize_name(text: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_]", "_", text)
    out = re.sub(r"_+", "_", out).strip("_")
    if not out:
        return "Unknown"
    if out[0].isdigit():
        out = "_" + out
    return out


def decompile_text(ifc, func) -> str:
    try:
        res = ifc.decompileFunction(func, 20, None)
        if not res.decompileCompleted():
            return ""
        return str(res.getDecompiledFunction().getC())
    except Exception:
        return ""


def is_unresolved_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("thunk_Cluster_")
    )


def classify_kind(fn_name: str, has_event: bool, has_lookup: bool, tag_count: int) -> str:
    if INIT_NAME_RE.search(fn_name):
        return "initializer"
    if HANDLER_NAME_RE.search(fn_name):
        return "handler"
    if has_event and (has_lookup or tag_count >= 2):
        return "handler"
    if tag_count >= 4 and not has_event:
        return "initializer"
    return "unknown"


def build_candidate_name(addr_int: int, tags: list[str]) -> str:
    chosen = []
    for t in TAG_PRIORITY:
        if t in tags:
            chosen.append(TAG_NAME_MAP.get(t, sanitize_name(t.title())))
        if len(chosen) >= 3:
            break
    if not chosen:
        chosen = [TAG_NAME_MAP.get(t, sanitize_name(t.title())) for t in tags[:3]]
    return f"Handle{''.join(chosen)}Commands_{addr_int:08x}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--detail-csv", required=True, help="Input detail CSV from extract_control_tag_usage.py")
    ap.add_argument(
        "--out-matrix-csv",
        default="tmp_decomp/command_tag_dispatch_matrix.csv",
        help="Output matrix CSV path",
    )
    ap.add_argument(
        "--out-candidate-csv",
        default="tmp_decomp/command_tag_handler_rename_candidates.csv",
        help="Output rename candidate CSV path",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    ap.add_argument(
        "--only-unresolved",
        action="store_true",
        help="Limit matrix rows to unresolved function names",
    )
    ap.add_argument(
        "--min-handler-score",
        type=int,
        default=6,
        help="Minimum score for rename candidate output",
    )
    ap.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="Optional max functions to process (0 = no limit)",
    )
    ap.add_argument(
        "--focus-tags",
        default=",".join(sorted(TAG_NAME_MAP.keys())),
        help="comma-separated tag_le values treated as command/dispatch tags",
    )
    args = ap.parse_args()

    detail_csv = Path(args.detail_csv)
    out_matrix_csv = Path(args.out_matrix_csv)
    out_candidate_csv = Path(args.out_candidate_csv)
    root = Path(args.project_root).resolve()
    if not detail_csv.exists():
        print(f"missing detail csv: {detail_csv}")
        return 1
    focus_tags = {t.strip() for t in args.focus_tags.split(",") if t.strip()}

    by_func: dict[str, dict] = defaultdict(
        lambda: {
            "function_addr": "",
            "function_name": "",
            "total_tag_hits": 0,
            "tag_hits": defaultdict(int),
        }
    )

    with detail_csv.open("r", encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        for row in rd:
            addr = (row.get("function_addr") or "").strip().lower()
            name = (row.get("function_name") or "").strip()
            tag = (row.get("tag_le") or "").strip()
            hits = int((row.get("hit_count") or "0").strip() or 0)
            if not addr or not name or not tag:
                continue
            agg = by_func[addr]
            agg["function_addr"] = addr
            agg["function_name"] = name
            agg["total_tag_hits"] += hits
            agg["tag_hits"][tag] += hits

    funcs = sorted(by_func.values(), key=lambda x: x["function_addr"])
    if args.only_unresolved:
        funcs = [x for x in funcs if is_unresolved_name(x["function_name"])]
    if args.max_functions > 0:
        funcs = funcs[: args.max_functions]

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    matrix_rows = []
    candidate_rows = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.app.decompiler import DecompInterface

        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        ifc = DecompInterface()
        ifc.openProgram(program)

        for entry in funcs:
            addr_txt = entry["function_addr"]
            addr_int = parse_hex(addr_txt)
            addr = af.getAddress(f"0x{addr_int:08x}")
            func = fm.getFunctionAt(addr)
            if func is None:
                continue

            fn_name = func.getName()
            signature = str(func.getSignature())
            tags_sorted = sorted(
                entry["tag_hits"].keys(), key=lambda t: (-entry["tag_hits"][t], t)
            )
            cmd_tags_sorted = [t for t in tags_sorted if t in focus_tags]
            tag_pairs = [f"{t}:{entry['tag_hits'][t]}" for t in tags_sorted]
            cmd_tag_pairs = [f"{t}:{entry['tag_hits'][t]}" for t in cmd_tags_sorted]
            tag_names = [TAG_NAME_MAP.get(t, t) for t in tags_sorted]
            cmd_tag_names = [TAG_NAME_MAP.get(t, t) for t in cmd_tags_sorted]

            callees = []
            ins_it = listing.getInstructions(func.getBody(), True)
            while ins_it.hasNext():
                ins = ins_it.next()
                if str(ins.getMnemonicString()).upper() != "CALL":
                    continue
                refs = ins.getReferencesFrom()
                for ref in refs:
                    cf = fm.getFunctionAt(ref.getToAddress())
                    if cf is None:
                        continue
                    nm = cf.getName()
                    if nm not in callees:
                        callees.append(nm)
                    if len(callees) >= 24:
                        break
                if len(callees) >= 24:
                    break

            c_text = decompile_text(ifc, func)
            has_event = bool(EVENT_RE.search(c_text))
            has_lookup = bool(LOOKUP_RE.search(c_text))
            bool_return = signature.strip().startswith("bool ")

            tag_count = len(tags_sorted)
            cmd_tag_count = len(cmd_tags_sorted)
            score = cmd_tag_count * 3 + (2 if has_event else 0) + (1 if has_lookup else 0) + (
                1 if bool_return else 0
            )
            kind = classify_kind(fn_name, has_event, has_lookup, cmd_tag_count)
            unresolved = is_unresolved_name(fn_name)

            matrix_rows.append(
                {
                    "function_addr": f"0x{addr_int:08x}",
                    "function_name": fn_name,
                    "signature": signature,
                    "kind": kind,
                    "unresolved": "1" if unresolved else "0",
                    "tag_count": str(tag_count),
                    "command_tag_count": str(cmd_tag_count),
                    "total_tag_hits": str(entry["total_tag_hits"]),
                    "tags": ",".join(tags_sorted),
                    "tag_names": ",".join(tag_names),
                    "tag_hits": ";".join(tag_pairs),
                    "command_tags": ",".join(cmd_tags_sorted),
                    "command_tag_names": ",".join(cmd_tag_names),
                    "command_tag_hits": ";".join(cmd_tag_pairs),
                    "has_event_pattern": "1" if has_event else "0",
                    "has_lookup_pattern": "1" if has_lookup else "0",
                    "bool_return": "1" if bool_return else "0",
                    "handler_score": str(score),
                    "sample_callees": ";".join(callees[:10]),
                }
            )

            if not unresolved:
                continue
            if kind != "handler":
                continue
            if score < args.min_handler_score:
                continue
            if cmd_tag_count == 0:
                continue

            new_name = build_candidate_name(addr_int, cmd_tags_sorted)
            comment = (
                "[DispatchMatrix] handler-like unresolved function; "
                f"tags={','.join(cmd_tags_sorted)} score={score} "
                f"event={int(has_event)} lookup={int(has_lookup)}"
            )
            candidate_rows.append(
                {
                    "address": f"0x{addr_int:08x}",
                    "new_name": new_name,
                    "comment": comment,
                    "old_name": fn_name,
                    "kind": kind,
                    "handler_score": str(score),
                    "tags": ",".join(cmd_tags_sorted),
                }
            )

    matrix_rows.sort(
        key=lambda r: (
            -int(r["handler_score"]),
            -int(r["tag_count"]),
            r["function_addr"],
        )
    )
    candidate_rows.sort(
        key=lambda r: (
            -int(r["handler_score"]),
            r["address"],
        )
    )

    out_matrix_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_matrix_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "function_addr",
                "function_name",
                "signature",
                "kind",
                "unresolved",
                "tag_count",
                "command_tag_count",
                "total_tag_hits",
                "tags",
                "tag_names",
                "tag_hits",
                "command_tags",
                "command_tag_names",
                "command_tag_hits",
                "has_event_pattern",
                "has_lookup_pattern",
                "bool_return",
                "handler_score",
                "sample_callees",
            ],
        )
        w.writeheader()
        w.writerows(matrix_rows)

    with out_candidate_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["address", "new_name", "comment", "old_name", "kind", "handler_score", "tags"],
        )
        w.writeheader()
        w.writerows(candidate_rows)

    print(f"[saved] matrix={out_matrix_csv} rows={len(matrix_rows)}")
    print(f"[saved] candidates={out_candidate_csv} rows={len(candidate_rows)}")
    for row in candidate_rows[:80]:
        print(
            f"{row['address']} {row['old_name']} -> {row['new_name']} "
            f"score={row['handler_score']} tags={row['tags']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
