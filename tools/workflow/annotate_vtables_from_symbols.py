#!/usr/bin/env python3
"""Add missing VTABLE annotations by matching class names to g_vtbl* symbols."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files, is_generated_source_path
from tools.common.pipe_csv import normalize_hex, read_pipe_map, read_pipe_rows
from tools.common.repo import repo_root_from_file


CLASS_DECL_RE = re.compile(r"^\s*(?:class|struct)\s+(?P<name>[A-Za-z_]\w*)\b")
VTABLE_SYMBOL_RE = re.compile(r"^g_vtbl(?P<class>[A-Za-z_]\w*)$")
VTABLE_ANNOT_RE = re.compile(
    r"^\s*//\s*VTABLE:\s*(?P<target>[A-Za-z0-9_]+)\s+0x(?P<addr>[0-9a-f]+)\s*$"
)


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--symbols-csv",
        default=str(repo_root / "config" / "symbols.csv"),
        help="Path to symbols.csv (pipe-delimited).",
    )
    parser.add_argument(
        "--target",
        default="IMPERIALISM",
        help="reccmp target/module id used in VTABLE annotations.",
    )
    parser.add_argument(
        "--overrides-csv",
        default=str(repo_root / "config" / "vtable_annotation_overrides.csv"),
        help=(
            "Optional override map (pipe-delimited): class|address. "
            "Used to resolve duplicate g_vtbl<Class> addresses."
        ),
    )
    parser.add_argument(
        "--duplicate-fallback",
        choices=("skip", "first"),
        default="first",
        help="How to resolve duplicate class->vtable addresses when no override exists.",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["include/game"],
        help="Files or directories to scan.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write changes in-place. Without this flag only prints planned edits.",
    )
    return parser.parse_args()


def load_override_map(path: Path) -> dict[str, str]:
    return read_pipe_map(path, key_column="class", value_column="address", normalize_value=normalize_hex)


def load_vtable_symbol_map(
    symbols_csv: Path, overrides: dict[str, str], duplicate_fallback: str
) -> tuple[dict[str, str], dict[str, int]]:
    by_class: dict[str, list[str]] = {}
    for row in read_pipe_rows(symbols_csv):
        if row.get("type") != "global":
            continue
        name = (row.get("name") or "").strip()
        if not name:
            continue
        match = VTABLE_SYMBOL_RE.match(name)
        if match is None:
            continue
        class_name = match.group("class")
        addr = normalize_hex((row.get("address") or "").strip())
        if not addr:
            continue
        by_class.setdefault(class_name, []).append(addr)

    resolved: dict[str, str] = {}
    stats = {"override": 0, "unique": 0, "first": 0, "skipped": 0}
    for class_name, addrs in by_class.items():
        unique_addrs = sorted(set(addrs))
        if len(unique_addrs) == 1:
            resolved[class_name] = unique_addrs[0]
            stats["unique"] += 1
            continue

        override_addr = overrides.get(class_name)
        if override_addr is not None and override_addr in set(unique_addrs):
            resolved[class_name] = override_addr
            stats["override"] += 1
            continue

        if duplicate_fallback == "first":
            resolved[class_name] = unique_addrs[0]
            stats["first"] += 1
            continue

        stats["skipped"] += 1
    return resolved, stats


def has_nearby_vtable_annotation(lines: list[str], idx: int, target: str) -> bool:
    start = max(0, idx - 4)
    for i in range(start, idx):
        match = VTABLE_ANNOT_RE.match(lines[i])
        if match is not None and match.group("target") == target:
            return True
    return False


def main() -> int:
    args = parse_args()
    symbols_csv = Path(args.symbols_csv)
    if not symbols_csv.exists():
        raise FileNotFoundError(f"Missing symbols CSV: {symbols_csv}")

    overrides = load_override_map(Path(args.overrides_csv))
    class_to_addr, resolve_stats = load_vtable_symbol_map(
        symbols_csv=symbols_csv,
        overrides=overrides,
        duplicate_fallback=args.duplicate_fallback,
    )

    files = iter_files(args.paths)
    total_added = 0
    changed_files = 0
    for path in files:
        if is_generated_source_path(path):
            continue

        original = path.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        output: list[str] = []
        added = 0
        for idx, line in enumerate(lines):
            match = CLASS_DECL_RE.match(line)
            if match is not None:
                class_name = match.group("name")
                addr = class_to_addr.get(class_name)
                if (
                    addr is not None
                    and not has_nearby_vtable_annotation(lines, idx, args.target)
                ):
                    output.append(f"// VTABLE: {args.target} 0x{addr}\n")
                    added += 1
            output.append(line)

        if added > 0:
            changed_files += 1
            total_added += added
            print(f"{path}: +{added} VTABLE annotations")
            if args.write:
                path.write_text("".join(output), encoding="utf-8")

    mode = "write" if args.write else "dry-run"
    print(f"Mode: {mode}")
    print(f"Files changed: {changed_files}")
    print(f"Annotations added: {total_added}")
    print(
        "Vtable map resolution: "
        f"unique={resolve_stats['unique']}, "
        f"override={resolve_stats['override']}, "
        f"first={resolve_stats['first']}, "
        f"skipped={resolve_stats['skipped']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
