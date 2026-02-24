#!/usr/bin/env python3
"""Add optional STRING/GLOBAL annotations for C string declarations."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Iterable


STRING_DECL_RE = re.compile(
    r"^\s*(?:static\s+)?(?:const\s+)?(?P<type>char|wchar_t)\s*(?P<pointer>\*?)\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<array>\[[^\]]*\])?\s*=\s*"
    r"(?P<literal>L?\"(?:[^\"\\]|\\.)*\")"
)
GLOBAL_ANNOT_RE = re.compile(
    r"^\s*//\s*GLOBAL:\s*(?P<target>[A-Za-z0-9_]+)\s+0x(?P<addr>[0-9a-f]+)\s*$"
)
STRING_ANNOT_RE = re.compile(
    r"^\s*//\s*STRING:\s*(?P<target>[A-Za-z0-9_]+)\s+0x(?P<addr>[0-9a-f]+)\s*$"
)


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--symbols-csv",
        default=str(repo_root / "config" / "symbols.csv"),
        help="Path to symbols.csv (pipe-delimited).",
    )
    parser.add_argument(
        "--global-overrides-csv",
        default=str(repo_root / "config" / "global_annotation_overrides.csv"),
        help="Optional name|address map used to resolve duplicate-name globals.",
    )
    parser.add_argument(
        "--string-overrides-csv",
        default=str(repo_root / "config" / "string_annotation_overrides.csv"),
        help=(
            "Optional name|string_address map for explicit STRING annotations. "
            "If absent, only array declarations can use GLOBAL addr as STRING addr."
        ),
    )
    parser.add_argument(
        "--target",
        default="IMPERIALISM",
        help="reccmp target/module id used in annotations.",
    )
    parser.add_argument(
        "--duplicate-fallback",
        choices=("skip", "first"),
        default="first",
        help="How to resolve duplicate-name globals when no override exists.",
    )
    parser.add_argument(
        "--array-uses-global-address",
        action="store_true",
        default=True,
        help=(
            "If true, for `char name[] = \"...\"` declarations without explicit string override, "
            "emit STRING with the same address as GLOBAL."
        ),
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


def iter_files(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        p = Path(item)
        if p.is_file():
            files.append(p)
            continue
        if p.is_dir():
            for ext in ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp"):
                files.extend(sorted(p.rglob(ext)))
    seen: set[Path] = set()
    ordered: list[Path] = []
    for f in sorted(files):
        rf = f.resolve()
        if rf in seen:
            continue
        seen.add(rf)
        ordered.append(f)
    return ordered


def load_name_to_addresses(symbols_csv: Path) -> dict[str, list[str]]:
    by_name: dict[str, list[str]] = {}
    with symbols_csv.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            if row.get("type") != "global":
                continue
            name = row.get("name", "").strip()
            addr = row.get("address", "").strip().lower().removeprefix("0x")
            if not name or not addr:
                continue
            by_name.setdefault(name, []).append(addr)
    return {name: sorted(set(addrs)) for name, addrs in by_name.items()}


def load_override_map(path: Path, key_column: str, addr_column: str) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        for row in reader:
            key = row.get(key_column, "").strip()
            addr = row.get(addr_column, "").strip().lower().removeprefix("0x")
            if not key or not addr:
                continue
            out[key] = addr
    return out


def resolve_global_addr(
    name: str,
    name_to_addrs: dict[str, list[str]],
    global_override: dict[str, str],
    duplicate_fallback: str,
) -> tuple[str | None, str]:
    addrs = name_to_addrs.get(name)
    if not addrs:
        return None, "missing"
    if len(addrs) == 1:
        return addrs[0], "unique"

    override = global_override.get(name)
    if override is not None and override in set(addrs):
        return override, "override"

    if duplicate_fallback == "first":
        return addrs[0], "first"
    return None, "unresolved"


def has_nearby_annotation(lines: list[str], idx: int, target: str, kind: str) -> bool:
    start = max(0, idx - 4)
    regex = GLOBAL_ANNOT_RE if kind == "global" else STRING_ANNOT_RE
    for i in range(start, idx):
        match = regex.match(lines[i])
        if match is not None and match.group("target") == target:
            return True
    return False


def main() -> int:
    args = parse_args()
    symbols_csv = Path(args.symbols_csv)
    if not symbols_csv.exists():
        raise FileNotFoundError(f"Missing symbols CSV: {symbols_csv}")

    name_to_addrs = load_name_to_addresses(symbols_csv)
    global_override = load_override_map(
        Path(args.global_overrides_csv), key_column="name", addr_column="address"
    )
    string_override = load_override_map(
        Path(args.string_overrides_csv), key_column="name", addr_column="string_address"
    )

    files = iter_files(args.paths)
    changed_files = 0
    global_added = 0
    string_added = 0
    resolve_stats = {"unique": 0, "override": 0, "first": 0, "unresolved": 0, "missing": 0}
    for path in files:
        path_posix = path.as_posix()
        if "/ghidra_autogen/" in path_posix or "/autogen/stubs/" in path_posix:
            continue

        original = path.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        output: list[str] = []
        file_global_added = 0
        file_string_added = 0

        for idx, line in enumerate(lines):
            match = STRING_DECL_RE.match(line)
            if match is not None:
                name = match.group("name")
                pointer = match.group("pointer")
                array_suffix = match.group("array")

                global_addr, mode = resolve_global_addr(
                    name=name,
                    name_to_addrs=name_to_addrs,
                    global_override=global_override,
                    duplicate_fallback=args.duplicate_fallback,
                )
                resolve_stats[mode] += 1

                string_addr = string_override.get(name)
                if (
                    string_addr is None
                    and array_suffix is not None
                    and pointer == ""
                    and args.array_uses_global_address
                ):
                    string_addr = global_addr

                if (
                    global_addr is not None
                    and not has_nearby_annotation(lines, idx, args.target, "global")
                ):
                    output.append(f"// GLOBAL: {args.target} 0x{global_addr}\n")
                    file_global_added += 1

                if (
                    string_addr is not None
                    and not has_nearby_annotation(lines, idx, args.target, "string")
                ):
                    output.append(f"// STRING: {args.target} 0x{string_addr}\n")
                    file_string_added += 1

            output.append(line)

        if file_global_added > 0 or file_string_added > 0:
            changed_files += 1
            global_added += file_global_added
            string_added += file_string_added
            print(
                f"{path}: +{file_global_added} GLOBAL, +{file_string_added} STRING annotations"
            )
            if args.write:
                path.write_text("".join(output), encoding="utf-8")

    mode = "write" if args.write else "dry-run"
    print(f"Mode: {mode}")
    print(f"Files changed: {changed_files}")
    print(f"GLOBAL annotations added: {global_added}")
    print(f"STRING annotations added: {string_added}")
    print(
        "Global address resolution: "
        f"unique={resolve_stats['unique']}, "
        f"override={resolve_stats['override']}, "
        f"first={resolve_stats['first']}, "
        f"unresolved={resolve_stats['unresolved']}, "
        f"missing={resolve_stats['missing']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
