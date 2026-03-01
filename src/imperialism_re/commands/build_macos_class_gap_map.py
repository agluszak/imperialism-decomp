#!/usr/bin/env python3
"""
Build per-class macOS vocabulary gaps against Windows class namespaces.

The output is a ranked, actionable queue that answers:
  - Which macOS class methods are still missing in Windows naming?
  - How many generic functions exist in that class namespace to absorb them?
  - Which classes should be prioritized first?

Output CSV columns:
  class_rank,class_name,macos_method,missing_count,windows_named_count,
  windows_unnamed_count,windows_method_count,class_xrefs_to_count,priority_score,
  candidate_addresses,candidate_names,evidence_kind
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import load_csv_rows, write_csv_rows
from imperialism_re.core.ghidra_session import open_program
from imperialism_re.core.wave_shared import is_unresolved_name


def _parse_class_filter(raw: str) -> set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


def _is_generic_name(name: str) -> bool:
    if is_unresolved_name(name):
        return True
    if name.startswith("thunk_FUN_"):
        return True
    if name.startswith("CreateSingleJmpThunk_"):
        return True
    if name.startswith("WrapperFor_Cluster_"):
        return True
    return False


def _format_addr(addr_int: int) -> str:
    return f"0x{addr_int:08x}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build ranked macOS class-method gap map for Windows class namespaces.",
    )
    ap.add_argument(
        "--macos-csv",
        default="tmp_decomp/macos_class_methods.csv",
        help="macOS class methods CSV (default: tmp_decomp/macos_class_methods.csv)",
    )
    ap.add_argument(
        "--out-csv",
        default="tmp_decomp/macos_class_gap_map.csv",
        help="Output CSV path (default: tmp_decomp/macos_class_gap_map.csv)",
    )
    ap.add_argument(
        "--classes",
        default="",
        help="Optional comma-separated class filter.",
    )
    ap.add_argument(
        "--top-classes",
        type=int,
        default=0,
        help="Keep only top-N ranked classes (0 = all, default: 0).",
    )
    ap.add_argument(
        "--candidate-limit",
        type=int,
        default=8,
        help="Max candidate generic functions shown per class row (default: 8).",
    )
    ap.add_argument(
        "--min-missing",
        type=int,
        default=1,
        help="Only include classes with at least this many missing methods (default: 1).",
    )
    ap.add_argument(
        "--actionable-only",
        action="store_true",
        help="Only include classes that have at least one generic function in namespace.",
    )
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)

    macos_csv = Path(args.macos_csv)
    if not macos_csv.is_absolute():
        macos_csv = root / macos_csv
    if not macos_csv.exists():
        print(f"[error] missing macOS CSV: {macos_csv}")
        return 1

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = root / out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    class_filter = _parse_class_filter(args.classes)

    macos_methods: dict[str, set[str]] = defaultdict(set)
    for row in load_csv_rows(macos_csv):
        class_name = (row.get("class") or "").strip()
        method_name = (row.get("method") or "").strip()
        if not class_name or not method_name:
            continue
        if class_filter and class_name not in class_filter:
            continue
        macos_methods[class_name].add(method_name)

    if not macos_methods:
        print("[error] no macOS classes loaded after filtering")
        return 1

    windows_named: dict[str, set[str]] = defaultdict(set)
    windows_unnamed: dict[str, list[tuple[int, str, int]]] = defaultdict(list)
    windows_total_count: dict[str, int] = defaultdict(int)
    class_xrefs_to_count: dict[str, int] = defaultdict(int)

    with open_program(root) as program:
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        fit = fm.getFunctions(True)
        while fit.hasNext():
            fn = fit.next()
            ns = fn.getParentNamespace()
            if ns is None:
                continue
            class_name = str(ns.getName())
            if class_name not in macos_methods:
                continue

            fn_name = str(fn.getName())
            fn_addr = fn.getEntryPoint().getOffset() & 0xFFFFFFFF
            xrefs_to = int(rm.getReferenceCountTo(fn.getEntryPoint()))

            windows_total_count[class_name] += 1
            class_xrefs_to_count[class_name] += xrefs_to

            if _is_generic_name(fn_name):
                windows_unnamed[class_name].append((fn_addr, fn_name, xrefs_to))
            else:
                windows_named[class_name].add(fn_name)

    class_rows: list[dict[str, str]] = []
    rankable: list[tuple[int, str]] = []

    class_missing_map: dict[str, list[str]] = {}
    for class_name, mac_methods in macos_methods.items():
        named = windows_named.get(class_name, set())
        missing = sorted(mac_methods - named)
        unnamed = windows_unnamed.get(class_name, [])
        unnamed_count = len(unnamed)
        missing_count = len(missing)

        if missing_count < args.min_missing:
            continue
        if args.actionable_only and unnamed_count == 0:
            continue

        xrefs_total = class_xrefs_to_count.get(class_name, 0)
        # Prioritize classes with larger naming gap, then unresolved headroom, then traffic.
        priority_score = (
            missing_count * 1000000
            + min(unnamed_count, 999) * 1000
            + min(xrefs_total, 999)
        )
        rankable.append((priority_score, class_name))
        class_missing_map[class_name] = missing

    if not rankable:
        write_csv_rows(
            out_csv,
            [],
            [
                "class_rank",
                "class_name",
                "macos_method",
                "missing_count",
                "windows_named_count",
                "windows_unnamed_count",
                "windows_method_count",
                "class_xrefs_to_count",
                "priority_score",
                "candidate_addresses",
                "candidate_names",
                "evidence_kind",
            ],
        )
        print(f"[saved] {out_csv} rows=0")
        return 0

    rankable.sort(key=lambda x: (-x[0], x[1]))
    class_rank: dict[str, int] = {class_name: idx + 1 for idx, (_, class_name) in enumerate(rankable)}

    allowed_classes: set[str]
    if args.top_classes > 0:
        allowed_classes = {class_name for _, class_name in rankable[: args.top_classes]}
    else:
        allowed_classes = {class_name for _, class_name in rankable}

    for class_name in sorted(allowed_classes, key=lambda c: class_rank[c]):
        missing = class_missing_map[class_name]
        unnamed = sorted(
            windows_unnamed.get(class_name, []),
            key=lambda item: (-item[2], item[0]),
        )
        candidate_subset = unnamed[: args.candidate_limit]
        candidate_addresses = ";".join(_format_addr(addr) for addr, _name, _xrefs in candidate_subset)
        candidate_names = ";".join(f"{name}@{_format_addr(addr)}" for addr, name, _xrefs in candidate_subset)

        for method_name in missing:
            class_rows.append(
                {
                    "class_rank": str(class_rank[class_name]),
                    "class_name": class_name,
                    "macos_method": method_name,
                    "missing_count": str(len(missing)),
                    "windows_named_count": str(len(windows_named.get(class_name, set()))),
                    "windows_unnamed_count": str(len(windows_unnamed.get(class_name, []))),
                    "windows_method_count": str(windows_total_count.get(class_name, 0)),
                    "class_xrefs_to_count": str(class_xrefs_to_count.get(class_name, 0)),
                    "priority_score": str(next(score for score, cls in rankable if cls == class_name)),
                    "candidate_addresses": candidate_addresses,
                    "candidate_names": candidate_names,
                    "evidence_kind": "macos_vocabulary_gap",
                }
            )

    write_csv_rows(
        out_csv,
        class_rows,
        [
            "class_rank",
            "class_name",
            "macos_method",
            "missing_count",
            "windows_named_count",
            "windows_unnamed_count",
            "windows_method_count",
            "class_xrefs_to_count",
            "priority_score",
            "candidate_addresses",
            "candidate_names",
            "evidence_kind",
        ],
    )

    classes_emitted = len({row["class_name"] for row in class_rows})
    print(
        f"[saved] {out_csv} rows={len(class_rows)} "
        f"classes={classes_emitted} top_classes={args.top_classes or 'all'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
