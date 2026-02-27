#!/usr/bin/env python3
"""
Generate dehardcoding candidates by mapping immediate constants to known domain IDs.

Primary mapping source is expected from Neo4j export JSON (id->metadata), e.g.:
  tmp_decomp/domain_constants_neo4j_seed.json

The script scans PUSH-immediate constants per function, matches them against known IDs,
and emits ranked candidates for comment/rename triage.

Usage:
  .venv/bin/python new_scripts/generate_constant_domain_candidates.py \
    --constants-json tmp_decomp/domain_constants_neo4j_seed.json \
    --out-csv tmp_decomp/constant_domain_candidates_batch1.csv

Optional filtering / apply:
  --function-regex "Trade|Diplomacy|Map|Civilian"
  --min-hits 2
  --require-nearby-call-regex "Bitmap|Picture|Cursor|Icon"
  --nearby-call-window 6
  --apply-comments
  --max-apply 30
  --min-matched-id 0
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
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


def parse_known_ids(path: Path) -> dict[int, dict[str, str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[int, dict[str, str]] = {}
    for k, v in raw.items():
        try:
            kid = int(k)
        except Exception:
            continue
        name = str(v.get("name", "")).strip() if isinstance(v, dict) else str(v)
        domain = str(v.get("domain", "unknown")).strip() if isinstance(v, dict) else "unknown"
        source = str(v.get("source", "unknown")).strip() if isinstance(v, dict) else "unknown"
        if not name:
            continue
        out[kid] = {"name": name, "domain": domain or "unknown", "source": source or "unknown"}
    return out


def format_hit(k: int, meta: dict[str, str], count: int) -> str:
    return f"{k}:{meta['name']}[{meta['domain']}]x{count}"


def marker_for_comment() -> str:
    return "[ConstDomain]"


def build_comment_line(domains: list[str], hits: list[str]) -> str:
    return f"{marker_for_comment()} domains={','.join(domains)} hits={'; '.join(hits)}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--constants-json",
        default="tmp_decomp/domain_constants_neo4j_seed.json",
        help="JSON mapping exported from Neo4j (id->name/domain/source)",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/constant_domain_candidates.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--function-regex",
        default="",
        help="Optional regex filter on function names",
    )
    ap.add_argument("--min-hits", type=int, default=1, help="Minimum total matched constant hits")
    ap.add_argument(
        "--max-id",
        type=int,
        default=20000,
        help="Only inspect immediates in [0, max-id]",
    )
    ap.add_argument(
        "--min-matched-id",
        type=int,
        default=0,
        help="Only inspect immediates in [min-matched-id, max-id]",
    )
    ap.add_argument(
        "--require-nearby-call-regex",
        default=(
            "Bitmap|Picture|Cursor|Icon|Load.*Resource|Set.*Bitmap|Set.*Picture|"
            "Apply.*Bitmap|Apply.*Picture"
        ),
        help=(
            "Only count matched PUSH constants that are followed (within window) by a CALL to "
            "a callee name matching this regex; set to empty string to disable."
        ),
    )
    ap.add_argument(
        "--nearby-call-window",
        type=int,
        default=6,
        help="Instruction look-ahead window for nearby CALL matching",
    )
    ap.add_argument(
        "--apply-comments",
        action="store_true",
        help="Apply/update function comments with constant-domain summary",
    )
    ap.add_argument(
        "--max-apply",
        type=int,
        default=0,
        help="If >0 and --apply-comments is set, limit number of comments applied",
    )
    ap.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path containing imperialism-decomp.gpr",
    )
    args = ap.parse_args()

    constants_path = Path(args.constants_json)
    if not constants_path.exists():
        print(f"missing constants json: {constants_path}")
        return 1

    known = parse_known_ids(constants_path)
    if not known:
        print("no known IDs loaded")
        return 1

    out_csv = Path(args.out_csv)
    root = Path(args.project_root).resolve()
    fn_re = re.compile(args.function_regex) if args.function_regex else None
    call_re = re.compile(args.require_nearby_call_regex) if args.require_nearby_call_regex else None

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    rows = []

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        listing = program.getListing()

        it = fm.getFunctions(True)
        while it.hasNext():
            f = it.next()
            fname = f.getName()
            if fn_re and not fn_re.search(fname):
                continue

            hits: dict[int, int] = defaultdict(int)
            # Pull instructions once so we can apply callsite-aware lookahead filtering.
            insns = []
            ins_it = listing.getInstructions(f.getBody(), True)
            while ins_it.hasNext():
                insns.append(ins_it.next())

            for i, ins in enumerate(insns):
                if str(ins.getMnemonicString()).upper() != "PUSH":
                    continue

                # If requested, only accept constants near a call to bitmap/cursor-like helpers.
                if call_re is not None:
                    near_match = False
                    hi = min(len(insns), i + 1 + max(0, args.nearby_call_window))
                    for j in range(i + 1, hi):
                        nxt = insns[j]
                        if str(nxt.getMnemonicString()).upper() != "CALL":
                            continue
                        refs = nxt.getReferencesFrom()
                        for ref in refs:
                            callee = fm.getFunctionAt(ref.getToAddress())
                            if callee is None:
                                continue
                            if call_re.search(callee.getName()):
                                near_match = True
                                break
                        if near_match:
                            break
                    if not near_match:
                        continue

                nops = ins.getNumOperands()
                for oi in range(nops):
                    sc = ins.getScalar(oi)
                    if sc is None:
                        continue
                    try:
                        val = int(sc.getUnsignedValue())
                    except Exception:
                        continue
                    if val < 0 or val > args.max_id:
                        continue
                    if val < args.min_matched_id:
                        continue
                    if val in known:
                        hits[val] += 1

            if not hits:
                continue

            total_hits = sum(hits.values())
            if total_hits < args.min_hits:
                continue

            domains = sorted({known[k]["domain"] for k in hits.keys()})
            ordered = sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))
            hit_desc = [format_hit(k, known[k], c) for k, c in ordered]

            rows.append(
                {
                    "address": str(f.getEntryPoint()),
                    "function_name": fname,
                    "hit_count": total_hits,
                    "unique_ids": len(hits),
                    "domain_count": len(domains),
                    "domains": ",".join(domains),
                    "matched_ids": ",".join(str(k) for k, _ in ordered),
                    "constants": " | ".join(hit_desc),
                }
            )

        rows.sort(
            key=lambda r: (
                -int(r["hit_count"]),
                -int(r["domain_count"]),
                -int(r["unique_ids"]),
                r["address"],
            )
        )

        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", newline="", encoding="utf-8") as fh:
            wr = csv.DictWriter(
                fh,
                fieldnames=[
                    "address",
                    "function_name",
                    "hit_count",
                    "unique_ids",
                    "domain_count",
                    "domains",
                    "matched_ids",
                    "constants",
                ],
            )
            wr.writeheader()
            wr.writerows(rows)

        print(
            f"[saved] {out_csv} functions={len(rows)} "
            f"known_ids={len(known)} min_hits={args.min_hits} "
            f"min_matched_id={args.min_matched_id}"
        )
        for r in rows[:120]:
            print(
                f"{r['address']},{r['function_name']},hits={r['hit_count']},"
                f"ids={r['unique_ids']},domains={r['domains']},"
                f"{r['constants']}"
            )

        if not args.apply_comments:
            return 0

        apply_rows = rows
        if args.max_apply > 0:
            apply_rows = rows[: args.max_apply]

        tx = program.startTransaction("Apply const-domain comments")
        ok = 0
        skip = 0
        fail = 0
        try:
            for r in apply_rows:
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(r["address"])
                f = fm.getFunctionAt(addr)
                if f is None:
                    fail += 1
                    continue
                domains = [d for d in r["domains"].split(",") if d]
                hits = [h.strip() for h in r["constants"].split("|") if h.strip()]
                new_line = build_comment_line(domains, hits[:12])
                old = f.getComment() or ""
                if marker_for_comment() in old:
                    base = "\n".join(
                        ln for ln in old.splitlines() if marker_for_comment() not in ln
                    ).strip()
                    merged = (base + "\n" + new_line).strip()
                else:
                    merged = (old.strip() + "\n" + new_line).strip() if old.strip() else new_line
                if merged == old:
                    skip += 1
                    continue
                f.setComment(merged)
                ok += 1
        except Exception as ex:
            fail += 1
            print(f"[apply-fail] {ex}")
        finally:
            program.endTransaction(tx, True)

        program.save("apply const-domain comments", None)
        print(f"[comments] applied={ok} skipped={skip} fail={fail}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
