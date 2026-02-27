#!/usr/bin/env python3
"""
Generate neutral implementation renames for Cluster_* rows using unresolved snapshot evidence.

Input:
  CSV from list_unresolved_functions_in_range.py

Output:
  address,new_name,comment

Policy:
  - source name must match --name-regex (default: ^Cluster_)
  - require minimum named callee count and instruction count
  - choose first non-generic, non-excluded named callee as anchor
  - produce neutral non-semantic names:
      Helper_Uses_<AnchorCallee>_At<addr>
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


def parse_int(text: str | None) -> int:
    try:
        return int((text or "").strip() or "0")
    except Exception:
        return 0


def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        return "Unknown"
    if s[0].isdigit():
        s = "_" + s
    return s


def is_generic(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("Cluster_")
        or name.startswith("WrapperFor_Cluster_")
    )


def parse_named_callees(raw: str) -> list[str]:
    out: list[str] = []
    for part in (raw or "").split(";"):
        token = part.strip()
        if not token:
            continue
        if "@" in token:
            token = token.split("@", 1)[0].strip()
        if token:
            out.append(token)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", required=True, help="Unresolved snapshot CSV")
    ap.add_argument("--out-csv", required=True, help="Output rename CSV")
    ap.add_argument("--name-regex", default=r"^Cluster_", help="Source function name regex")
    ap.add_argument("--min-named-callees", type=int, default=2)
    ap.add_argument("--min-instruction-count", type=int, default=12)
    ap.add_argument(
        "--exclude-callee-regex",
        default=(
            r"^(AllocateWithFallbackHandler|InitializeSharedStringRefFromEmpty|"
            r"ReleaseSharedStringRefIfNotEmpty|AfxGetThread|__ftol|NoOpRuntimeCallback_)"
        ),
        help="Reject anchor callees matching this regex",
    )
    ap.add_argument("--max-rows", type=int, default=0, help="Optional cap after scoring")
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_csv = Path(args.out_csv)
    if not in_csv.exists():
        print(f"[error] missing input csv: {in_csv}")
        return 1

    name_re = re.compile(args.name_regex)
    exclude_re = re.compile(args.exclude_callee_regex)

    rows = list(csv.DictReader(in_csv.open("r", encoding="utf-8", newline="")))
    out: list[dict[str, str]] = []

    for r in rows:
        src_name = (r.get("name") or "").strip()
        if not name_re.search(src_name):
            continue

        addr = (r.get("address") or "").strip().lower()
        if not addr.startswith("0x"):
            continue
        addr_hex = addr[2:]

        named_callee_count = parse_int(r.get("named_callee_count"))
        instruction_count = parse_int(r.get("instruction_count"))
        if named_callee_count < args.min_named_callees:
            continue
        if instruction_count < args.min_instruction_count:
            continue

        callees = parse_named_callees(r.get("named_callees") or "")
        if not callees:
            continue

        anchor = ""
        for c in callees:
            if is_generic(c):
                continue
            if exclude_re.search(c):
                continue
            anchor = c
            break
        if not anchor:
            continue

        safe_anchor = sanitize_symbol_name(anchor)
        if len(safe_anchor) > 64:
            safe_anchor = safe_anchor[:64].rstrip("_")
        new_name = f"Helper_Uses_{safe_anchor}_At{addr_hex}"

        sample = ";".join(callees[:4])
        out.append(
            {
                "address": addr,
                "new_name": new_name,
                "comment": (
                    "[CalleeAnchor] unresolved Cluster_* renamed with named-callee anchor; "
                    f"named_callee_count={named_callee_count}; anchor={anchor}; sample={sample}"
                ),
                "_score_named": str(named_callee_count),
                "_score_instr": str(instruction_count),
            }
        )

    out.sort(
        key=lambda x: (
            -int(x["_score_named"]),
            -int(x["_score_instr"]),
            x["address"],
        )
    )
    if args.max_rows > 0:
        out = out[: args.max_rows]

    final_rows = [{"address": r["address"], "new_name": r["new_name"], "comment": r["comment"]} for r in out]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        w.writeheader()
        w.writerows(final_rows)

    print(
        f"[saved] {out_csv} rows={len(final_rows)} "
        f"min_named_callees={args.min_named_callees} min_instruction_count={args.min_instruction_count}"
    )
    for r in final_rows[:160]:
        print(f"{r['address']},{r['new_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
