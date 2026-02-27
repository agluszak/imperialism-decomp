#!/usr/bin/env python3
"""
Inventory datatype hierarchy roots and detect canonical-path collisions.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.datatypes import (
    DEFAULT_CANONICAL_PROJECT_ROOT,
    DEFAULT_LEGACY_PROJECT_ROOTS,
    build_datatype_path,
    canonicalize_category_path,
    category_is_under_root,
    category_root_of,
    datatype_richness_tuple,
    normalize_root_path,
    parse_roots_csv,
)
from imperialism_re.core.ghidra_session import open_program


def choose_winner(records: list[dict[str, str]]) -> dict[str, str]:
    def key(rec: dict[str, str]):
        return (
            int(rec["rich_kind_rank"]),
            int(rec["rich_components"]),
            int(rec["rich_enum_members"]),
            int(rec["rich_fn_args"]),
            int(rec["rich_length"]),
            int(rec["is_canonical_path"]),
            -len(rec["full_path"]),
            rec["full_path"],
        )

    return max(records, key=key)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--roots",
        default=",".join((DEFAULT_CANONICAL_PROJECT_ROOT, *DEFAULT_LEGACY_PROJECT_ROOTS, "/")),
        help="Comma-separated category roots to inventory",
    )
    ap.add_argument("--canonical-root", default=DEFAULT_CANONICAL_PROJECT_ROOT)
    ap.add_argument("--out-summary-csv", required=True)
    ap.add_argument("--out-collisions-csv", required=True)
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    scan_roots = parse_roots_csv(args.roots)
    canonical_root = normalize_root_path(args.canonical_root)
    if canonical_root not in scan_roots:
        scan_roots.append(canonical_root)
    project_roots = [r for r in scan_roots if r != "/"]

    out_summary = Path(args.out_summary_csv)
    out_collisions = Path(args.out_collisions_csv)
    if not out_summary.is_absolute():
        out_summary = root / out_summary
    if not out_collisions.is_absolute():
        out_collisions = root / out_collisions

    with open_program(root) as program:
        dtm = program.getDataTypeManager()
        rows_all: list[dict[str, str]] = []
        counts: dict[str, int] = {r: 0 for r in scan_roots}
        cats: dict[str, set[str]] = {r: set() for r in scan_roots}
        groups: dict[str, list[dict[str, str]]] = {}

        it = dtm.getAllDataTypes()
        while it.hasNext():
            dt = it.next()
            try:
                name = str(dt.getName())
                cat = str(dt.getCategoryPath().getPath())
                full_path = str(dt.getPathName())
                dtype_root = category_root_of(cat, scan_roots)
                if dtype_root is None:
                    continue
                rich = datatype_richness_tuple(dt)
                canonical_cat = canonicalize_category_path(
                    cat, canonical_root=canonical_root, source_roots=project_roots
                )
                canonical_path = build_datatype_path(canonical_cat, name)
                is_project = int(any(category_is_under_root(cat, r) for r in project_roots))
                row = {
                    "name": name,
                    "kind": str(dt.getClass().getSimpleName()),
                    "category_path": cat,
                    "full_path": full_path,
                    "root": dtype_root,
                    "canonical_path": canonical_path,
                    "is_canonical_path": str(int(full_path == canonical_path)),
                    "is_project": str(is_project),
                    "rich_kind_rank": str(rich[0]),
                    "rich_components": str(rich[1]),
                    "rich_enum_members": str(rich[2]),
                    "rich_fn_args": str(rich[3]),
                    "rich_length": str(rich[4]),
                }
                rows_all.append(row)
                counts[dtype_root] = counts.get(dtype_root, 0) + 1
                cats.setdefault(dtype_root, set()).add(cat)
                if is_project:
                    groups.setdefault(canonical_path, []).append(row)
            except Exception:
                continue

    collision_rows: list[dict[str, str]] = []
    collision_group_count = 0
    for canonical_path in sorted(groups.keys()):
        group = groups[canonical_path]
        if len(group) <= 1:
            continue
        collision_group_count += 1
        winner = choose_winner(group)
        winner_path = winner["full_path"]
        for rec in sorted(group, key=lambda x: x["full_path"]):
            row = dict(rec)
            row["collision_group_size"] = str(len(group))
            row["winner_full_path"] = winner_path
            row["winner_is_this_row"] = str(int(rec["full_path"] == winner_path))
            collision_rows.append(row)

    summary_rows = []
    for root_name in scan_roots:
        summary_rows.append(
            {
                "root": root_name,
                "datatype_count": str(counts.get(root_name, 0)),
                "category_count": str(len(cats.get(root_name, set()))),
            }
        )
    summary_rows.append(
        {
            "root": "__project_collision_groups__",
            "datatype_count": str(collision_group_count),
            "category_count": str(len(collision_rows)),
        }
    )

    write_csv_rows(
        out_summary,
        summary_rows,
        ["root", "datatype_count", "category_count"],
    )
    write_csv_rows(
        out_collisions,
        collision_rows,
        [
            "canonical_path",
            "name",
            "kind",
            "category_path",
            "full_path",
            "root",
            "is_canonical_path",
            "is_project",
            "rich_kind_rank",
            "rich_components",
            "rich_enum_members",
            "rich_fn_args",
            "rich_length",
            "collision_group_size",
            "winner_full_path",
            "winner_is_this_row",
        ],
    )

    print(f"[summary] roots={len(scan_roots)} rows={len(summary_rows)} csv={out_summary}")
    print(
        f"[collisions] groups={collision_group_count} rows={len(collision_rows)} csv={out_collisions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
