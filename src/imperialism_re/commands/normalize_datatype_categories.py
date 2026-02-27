#!/usr/bin/env python3
"""
Normalize project datatype categories to a single canonical root.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from imperialism_re.core.config import default_project_root, resolve_project_root
from imperialism_re.core.csvio import write_csv_rows
from imperialism_re.core.datatypes import (
    DEFAULT_CANONICAL_PROJECT_ROOT,
    DEFAULT_LEGACY_PROJECT_ROOTS,
    build_datatype_path,
    canonicalize_category_path,
    category_is_under_root,
    compare_datatype_richness,
    normalize_root_path,
    parse_roots_csv,
)
from imperialism_re.core.ghidra_session import open_program


def load_override_winners(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    rows = csv.DictReader(path.open("r", encoding="utf-8", newline=""))
    for row in rows:
        canonical = (row.get("canonical_path") or "").strip()
        winner = (row.get("winner_full_path") or "").strip()
        if not canonical or not winner:
            continue
        out[canonical] = winner
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canonical-root", default=DEFAULT_CANONICAL_PROJECT_ROOT)
    ap.add_argument(
        "--source-roots",
        default=",".join((DEFAULT_CANONICAL_PROJECT_ROOT, *DEFAULT_LEGACY_PROJECT_ROOTS)),
        help="Comma-separated roots to canonicalize (canonical root may be included)",
    )
    ap.add_argument(
        "--duplicate-policy",
        choices=["richer", "canonical", "manual"],
        default="richer",
    )
    ap.add_argument(
        "--collision-csv",
        default="",
        help="Optional collisions CSV with canonical_path,winner_full_path override",
    )
    ap.add_argument("--out-moved-csv", default="", help="Optional output CSV for moved rows")
    ap.add_argument("--out-resolved-csv", default="", help="Optional output CSV for resolved collisions")
    ap.add_argument("--out-skipped-csv", default="", help="Optional output CSV for skipped rows")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--project-root", default=default_project_root())
    args = ap.parse_args()

    root = resolve_project_root(args.project_root)
    canonical_root = normalize_root_path(args.canonical_root)
    source_roots = parse_roots_csv(args.source_roots)
    if canonical_root not in source_roots:
        source_roots.append(canonical_root)
    noncanonical_roots = [r for r in source_roots if r != canonical_root and r != "/"]
    if not noncanonical_roots:
        print("[error] source roots must include at least one non-canonical project root")
        return 1

    overrides: dict[str, str] = {}
    if args.collision_csv:
        collision_csv = Path(args.collision_csv)
        if not collision_csv.is_absolute():
            collision_csv = root / collision_csv
        if collision_csv.exists():
            overrides = load_override_winners(collision_csv)
        else:
            print(f"[warn] collision csv not found: {collision_csv}")

    with open_program(root) as program:
        from ghidra.program.model.data import CategoryPath

        dtm = program.getDataTypeManager()

        plans: list[dict[str, str]] = []
        it = dtm.getAllDataTypes()
        while it.hasNext():
            dt = it.next()
            try:
                name = str(dt.getName())
                src_cat = str(dt.getCategoryPath().getPath())
                if not any(category_is_under_root(src_cat, r) for r in noncanonical_roots):
                    continue
                src_full = str(dt.getPathName())
                dst_cat = canonicalize_category_path(
                    src_cat, canonical_root=canonical_root, source_roots=source_roots
                )
                dst_full = build_datatype_path(dst_cat, name)
                if src_full == dst_full:
                    continue

                dst_dt = dtm.getDataType(dst_full)
                if dst_dt is None:
                    plans.append(
                        {
                            "action": "move",
                            "policy": "none",
                            "source_path": src_full,
                            "dest_path": dst_full,
                            "winner_path": src_full,
                            "message": "move to canonical root",
                        }
                    )
                    continue

                cmp = compare_datatype_richness(dt, dst_dt)
                winner = dst_full
                message = "prefer canonical existing type"
                if args.duplicate_policy == "richer":
                    if cmp > 0:
                        winner = src_full
                        message = "source richer than canonical"
                    else:
                        winner = dst_full
                        message = "canonical richer or equal"
                elif args.duplicate_policy == "canonical":
                    winner = dst_full
                    message = "canonical policy"
                elif args.duplicate_policy == "manual":
                    override = overrides.get(dst_full)
                    if override:
                        winner = override
                        message = f"manual override: {override}"
                    else:
                        winner = ""
                        message = "manual policy without override"

                plans.append(
                    {
                        "action": "collision",
                        "policy": args.duplicate_policy,
                        "source_path": src_full,
                        "dest_path": dst_full,
                        "winner_path": winner,
                        "message": message,
                    }
                )
            except Exception as ex:
                plans.append(
                    {
                        "action": "error",
                        "policy": args.duplicate_policy,
                        "source_path": "<unknown>",
                        "dest_path": "<unknown>",
                        "winner_path": "",
                        "message": f"scan error: {ex}",
                    }
                )

        plans.sort(key=lambda x: (x["action"], x["source_path"], x["dest_path"]))
        move_count = sum(1 for p in plans if p["action"] == "move")
        coll_count = sum(1 for p in plans if p["action"] == "collision")
        print(
            f"[plan] total={len(plans)} moves={move_count} collisions={coll_count} apply={int(args.apply)}"
        )
        for p in plans[:220]:
            print(
                f"  {p['action']} src={p['source_path']} dst={p['dest_path']} "
                f"winner={p['winner_path'] or '<none>'} note={p['message']}"
            )
        if len(plans) > 220:
            print(f"  ... ({len(plans) - 220} more)")

        if not args.apply:
            print("[dry-run] pass --apply to write changes")
            return 0

        moved_rows: list[dict[str, str]] = []
        resolved_rows: list[dict[str, str]] = []
        skipped_rows: list[dict[str, str]] = []
        failed_rows: list[dict[str, str]] = []

        tx = program.startTransaction("Normalize datatype categories")
        ok = skip = fail = 0
        try:
            for p in plans:
                action = p["action"]
                src_path = p["source_path"]
                dst_path = p["dest_path"]
                winner = p["winner_path"]
                try:
                    if action == "move":
                        dt = dtm.getDataType(src_path)
                        if dt is None:
                            skip += 1
                            skipped_rows.append({**p, "result": "missing source at apply"})
                            continue
                        dst_cat = str(dst_path[: dst_path.rfind("/")])
                        dt.setCategoryPath(CategoryPath(dst_cat))
                        ok += 1
                        moved_rows.append({**p, "result": "moved"})
                        continue

                    if action == "collision":
                        if not winner:
                            skip += 1
                            skipped_rows.append({**p, "result": "manual unresolved"})
                            continue
                        src_dt = dtm.getDataType(src_path)
                        dst_dt = dtm.getDataType(dst_path)
                        if src_dt is None or dst_dt is None:
                            skip += 1
                            skipped_rows.append({**p, "result": "missing source or destination at apply"})
                            continue
                        if winner == src_path:
                            dtm.replaceDataType(dst_dt, src_dt, True)
                            ok += 1
                            resolved_rows.append({**p, "result": "replaced canonical with richer source"})
                        elif winner == dst_path:
                            dtm.replaceDataType(src_dt, dst_dt, False)
                            ok += 1
                            resolved_rows.append({**p, "result": "repointed source to canonical"})
                        else:
                            skip += 1
                            skipped_rows.append({**p, "result": f"winner path unsupported: {winner}"})
                        continue

                    skip += 1
                    skipped_rows.append({**p, "result": f"ignored action={action}"})
                except Exception as ex:
                    fail += 1
                    failed_rows.append({**p, "result": f"error: {ex}"})
        finally:
            program.endTransaction(tx, True)

        program.save("normalize datatype categories", None)
        print(
            f"[done] ok={ok} skip={skip} fail={fail} moved={len(moved_rows)} "
            f"resolved={len(resolved_rows)} failed={len(failed_rows)}"
        )

    def _resolve_out(path_text: str) -> Path | None:
        if not path_text:
            return None
        p = Path(path_text)
        if not p.is_absolute():
            p = root / p
        return p

    out_moved = _resolve_out(args.out_moved_csv)
    out_resolved = _resolve_out(args.out_resolved_csv)
    out_skipped = _resolve_out(args.out_skipped_csv)
    if out_moved is not None:
        write_csv_rows(
            out_moved,
            moved_rows,
            ["action", "policy", "source_path", "dest_path", "winner_path", "message", "result"],
        )
        print(f"[csv] moved={len(moved_rows)} path={out_moved}")
    if out_resolved is not None:
        write_csv_rows(
            out_resolved,
            resolved_rows + failed_rows,
            ["action", "policy", "source_path", "dest_path", "winner_path", "message", "result"],
        )
        print(f"[csv] resolved={len(resolved_rows) + len(failed_rows)} path={out_resolved}")
    if out_skipped is not None:
        write_csv_rows(
            out_skipped,
            skipped_rows,
            ["action", "policy", "source_path", "dest_path", "winner_path", "message", "result"],
        )
        print(f"[csv] skipped={len(skipped_rows)} path={out_skipped}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
