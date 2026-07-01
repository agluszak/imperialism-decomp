#!/usr/bin/env python3
"""Sync function ownership CSV from manual reccmp markers in source files."""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.function_ownership import (
    DEFAULT_FUNCTION_OWNERSHIP_CSV,
    FunctionOwnership,
    load_function_ownership,
    normalize_repo_relative_path,
    write_function_ownership,
)


MARKER_RE_TEMPLATE = (
    r"//\s*(?P<kind>FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*{target}\s+"
    r"(?:0x)?(?P<address>[0-9a-fA-F]+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument(
        "--source-dir",
        action="append",
        default=None,
        help="Directory to scan for markers (repeatable; default: src and include).",
    )
    parser.add_argument("--ownership-csv", default=DEFAULT_FUNCTION_OWNERSHIP_CSV)
    parser.add_argument(
        "--no-prune-missing-manual",
        dest="prune_missing_manual",
        action="store_false",
        help="Keep stale non-autogen ownership rows whose markers no longer exist. "
        "Pruning is the default: a stale manual row silently suppresses stub "
        "regeneration for that address.",
    )
    parser.set_defaults(prune_missing_manual=True)
    return parser.parse_args()


def should_skip_path(path: Path) -> bool:
    posix = path.as_posix()
    return "/ghidra_autogen/" in posix or "/autogen/" in posix


def iter_source_files(source_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx"):
        files.extend(sorted(source_dir.rglob(pattern)))
    return files


def collect_marker_ownership(
    source_dir: Path, repo_root: Path, target: str
) -> tuple[dict[int, FunctionOwnership], list[tuple[int, str, str]]]:
    import re

    marker_re = re.compile(MARKER_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE)
    found: dict[int, FunctionOwnership] = {}
    conflicts: list[tuple[int, str, str]] = []

    for path in iter_source_files(source_dir):
        if should_skip_path(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        target_cpp = normalize_repo_relative_path(path, repo_root)
        for match in marker_re.finditer(text):
            address = int(match.group("address"), 16)
            marker_kind = match.group("kind").upper()
            entry = FunctionOwnership(
                address=address,
                target_cpp=target_cpp,
                ownership="library" if marker_kind == "LIBRARY" else "manual",
                note="marker_sync",
            )
            existing = found.get(address)
            if existing is None:
                found[address] = entry
                continue
            if existing.target_cpp != entry.target_cpp:
                conflicts.append((address, existing.target_cpp, entry.target_cpp))
    return found, conflicts


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    source_dirs = args.source_dir or ["src", "include"]
    scanned_entries: dict[int, FunctionOwnership] = {}
    conflicts: list[tuple[int, str, str]] = []
    ownership_csv = resolve_repo_path(repo_root, args.ownership_csv)

    for source_dir_arg in source_dirs:
        source_dir = resolve_repo_path(repo_root, source_dir_arg)
        if not source_dir.is_dir():
            raise SystemExit(f"Missing source directory: {source_dir}")
        entries, dir_conflicts = collect_marker_ownership(
            source_dir=source_dir, repo_root=repo_root, target=args.target
        )
        conflicts.extend(dir_conflicts)
        for address, entry in entries.items():
            existing = scanned_entries.get(address)
            if existing is not None and existing.target_cpp != entry.target_cpp:
                conflicts.append((address, existing.target_cpp, entry.target_cpp))
                continue
            scanned_entries.setdefault(address, entry)
    if conflicts:
        msg = ", ".join(
            f"0x{addr:08X}: {lhs} vs {rhs}" for addr, lhs, rhs in sorted(conflicts)
        )
        raise SystemExit("Conflicting ownership markers found: " + msg)

    merged = load_function_ownership(ownership_csv)
    stale_manual = 0
    if args.prune_missing_manual:
        mention_cache: dict[str, str] = {}

        def file_mentions_address(target_cpp: str, address: int) -> bool:
            """A marker-less ownership row is load-bearing (a deliberate stub
            suppression) when its file or the matching class header still mentions
            the address: shape-only vtable classes carry it in slot comments and
            OrphanRetStub_<addr> method names, and their recomp symbols pair with
            the original by NAME, so an autogen stub at the address would steal
            the pairing (it broke 364/379 vtable comparisons)."""
            paths = [Path(target_cpp)]
            stem = Path(target_cpp).stem
            paths.append(Path("include/game") / (stem + ".h"))
            for rel in paths:
                path = resolve_repo_path(repo_root, rel.as_posix())
                key = path.as_posix()
                if key not in mention_cache:
                    try:
                        mention_cache[key] = path.read_text(
                            encoding="utf-8", errors="ignore"
                        ).lower()
                    except OSError:
                        mention_cache[key] = ""
                text = mention_cache[key]
                if format(address, "x") in text or format(address, "08x") in text:
                    return True
            return False

        for address in list(merged.keys()):
            entry = merged[address]
            if entry.ownership.lower() == "autogen":
                continue
            if entry.note.strip().lower() != "marker_sync":
                # Only reconcile rows this tool created. Any other note (e.g.
                # mfc_runtime_macro) is a curated suppression: the address is owned
                # by code with no marker (macro emissions, name-paired methods).
                continue
            if address in scanned_entries:
                continue
            if file_mentions_address(entry.target_cpp, address):
                continue
            stale_manual += 1
            del merged[address]

    updates = 0
    for address, entry in scanned_entries.items():
        if merged.get(address) != entry:
            updates += 1
        merged[address] = entry

    write_function_ownership(ownership_csv, merged)
    print(f"Scanned marker-owned functions: {len(scanned_entries)}")
    print(f"Ownership updates: {updates}")
    if args.prune_missing_manual:
        print(f"Pruned missing non-autogen ownership rows: {stale_manual}")
    print(f"Wrote {ownership_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
