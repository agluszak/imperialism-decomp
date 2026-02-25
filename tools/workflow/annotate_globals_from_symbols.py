#!/usr/bin/env python3
"""Add missing GLOBAL annotations by matching variable names to symbols.csv.

Duplicate-name symbols are resolved via:
1) override file,
2) address suffix in the variable name,
3) address literal context inside the file,
4) deterministic first-address fallback (optional).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files, is_generated_source_path
from tools.common.pipe_csv import normalize_hex, read_pipe_map, read_pipe_rows
from tools.common.repo import repo_root_from_file

DECL_RE = re.compile(
    r"^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?"
    r"(?:char|short|int|long|float|double|void\*|[A-Za-z_]\w*(?:\s*::\s*\w+)*\s*\*?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=|;|\[)"
)

GLOBAL_ANNOT_RE = re.compile(
    r"^\s*//\s*GLOBAL:\s*(?P<target>[A-Za-z0-9_]+)\s+0x(?P<addr>[0-9a-f]+)\s*$"
)

HEX_LITERAL_RE = re.compile(r"0x([0-9a-fA-F]+)")
NAME_ADDR_SUFFIX_RE = re.compile(r"_([0-9A-Fa-f]{6,8})$")


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
        help="reccmp target/module id used in GLOBAL annotations.",
    )
    parser.add_argument(
        "--overrides-csv",
        default=str(repo_root / "config" / "global_annotation_overrides.csv"),
        help=(
            "Optional override map (pipe-delimited): name|address. "
            "Used to resolve duplicate-name globals."
        ),
    )
    parser.add_argument(
        "--duplicate-fallback",
        choices=("skip", "first"),
        default="first",
        help="How to resolve duplicate-name globals when no override/context match exists.",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["src/game", "include/game"],
        help="Files or directories to scan.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write changes in-place. Without this flag only prints planned edits.",
    )
    return parser.parse_args()


def load_global_symbols(path: Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    by_name: dict[str, list[str]] = {}
    for row in read_pipe_rows(path):
        if row.get("type") != "global":
            continue
        name = (row.get("name") or "").strip()
        addr = (row.get("address") or "").strip()
        if not name or not addr:
            continue
        by_name.setdefault(name, []).append(normalize_hex(addr))

    unique: dict[str, str] = {}
    duplicates: dict[str, list[str]] = {}
    for name, addrs in by_name.items():
        unique_addrs = sorted(set(addrs))
        if len(unique_addrs) == 1:
            unique[name] = unique_addrs[0]
        else:
            duplicates[name] = unique_addrs
    return unique, duplicates


def load_override_map(path: Path) -> dict[str, str]:
    return read_pipe_map(path, key_column="name", value_column="address", normalize_value=normalize_hex)


def has_nearby_global_annotation(lines: list[str], idx: int, target: str) -> bool:
    start = max(0, idx - 4)
    for i in range(start, idx):
        match = GLOBAL_ANNOT_RE.match(lines[i])
        if match is None:
            continue
        # If a GLOBAL marker is directly associated with this declaration block, keep it.
        if match.group("target") == target:
            return True
    return False


def collect_file_hex_literals(lines: list[str]) -> set[int]:
    values: set[int] = set()
    for line in lines:
        for match in HEX_LITERAL_RE.finditer(line):
            try:
                values.add(int(match.group(1), 16))
            except ValueError:
                continue
    return values


def parse_hex_value(addr_hex: str) -> int:
    return int(addr_hex.lower().removeprefix("0x"), 16)


def normalize_addr(addr_hex: str) -> str:
    return normalize_hex(addr_hex)


def resolve_duplicate_address(
    name: str,
    candidates: list[str],
    file_hex_literals: set[int],
    override_map: dict[str, str],
    duplicate_fallback: str,
) -> tuple[str | None, str]:
    normalized_candidates = [normalize_addr(c) for c in candidates]
    candidate_set = set(normalized_candidates)

    override_addr = override_map.get(name)
    if override_addr is not None and override_addr in candidate_set:
        return override_addr, "override"

    suffix_match = NAME_ADDR_SUFFIX_RE.search(name)
    if suffix_match is not None:
        suffix_addr = normalize_addr(suffix_match.group(1))
        if suffix_addr in candidate_set:
            return suffix_addr, "name-suffix"

    in_file = [
        addr for addr in normalized_candidates if parse_hex_value(addr) in file_hex_literals
    ]
    if len(in_file) == 1:
        return in_file[0], "file-context"

    if duplicate_fallback == "first":
        return normalized_candidates[0], "first"

    return None, "unresolved"


def main() -> int:
    args = parse_args()
    symbols_csv = Path(args.symbols_csv)
    if not symbols_csv.exists():
        raise FileNotFoundError(f"Missing symbols CSV: {symbols_csv}")

    files = iter_files(args.paths)
    unique_globals, duplicate_globals = load_global_symbols(symbols_csv)
    override_map = load_override_map(Path(args.overrides_csv))

    total_added = 0
    changed_files = 0
    duplicate_stats = {
        "override": 0,
        "name-suffix": 0,
        "file-context": 0,
        "first": 0,
        "unresolved": 0,
    }
    for path in files:
        if is_generated_source_path(path):
            continue

        original = path.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        file_hex_literals = collect_file_hex_literals(lines)
        output: list[str] = []
        added = 0
        for idx, line in enumerate(lines):
            decl_match = DECL_RE.match(line)
            if decl_match is not None:
                name = decl_match.group("name")
                addr: str | None = unique_globals.get(name)
                if addr is None and name in duplicate_globals:
                    addr, mode = resolve_duplicate_address(
                        name=name,
                        candidates=duplicate_globals[name],
                        file_hex_literals=file_hex_literals,
                        override_map=override_map,
                        duplicate_fallback=args.duplicate_fallback,
                    )
                    duplicate_stats[mode] += 1

                if (
                    addr is not None
                    and not has_nearby_global_annotation(lines, idx, args.target)
                ):
                    output.append(f"// GLOBAL: {args.target} 0x{addr}\n")
                    added += 1
            output.append(line)

        if added > 0:
            changed_files += 1
            total_added += added
            print(f"{path}: +{added} GLOBAL annotations")
            if args.write:
                path.write_text("".join(output), encoding="utf-8")

    mode = "write" if args.write else "dry-run"
    print(f"Mode: {mode}")
    print(f"Files changed: {changed_files}")
    print(f"Annotations added: {total_added}")
    print(f"Duplicate global names in symbols.csv: {len(duplicate_globals)}")
    print(
        "Duplicate resolution usage: "
        f"override={duplicate_stats['override']}, "
        f"name-suffix={duplicate_stats['name-suffix']}, "
        f"file-context={duplicate_stats['file-context']}, "
        f"first={duplicate_stats['first']}, "
        f"unresolved={duplicate_stats['unresolved']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
