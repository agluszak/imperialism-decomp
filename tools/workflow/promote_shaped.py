#!/usr/bin/env python3
"""Promote autogen blocks into a manual file with optional shape_body pass.

Wraps ``promote_from_autogen`` collection/merge logic but shapes each block when
the owning class has a ``config/classes/<Class>.yml`` manifest (via ``gen_class``).
Falls back to a bare ``// FUNCTION:`` marker rewrite when no slot signature exists.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.thunk_names import ThunkResolver
from tools.workflow.function_ownership import (
    DEFAULT_FUNCTION_OWNERSHIP_CSV,
    FunctionOwnership,
    load_function_ownership,
    normalize_repo_relative_path,
    parse_hex_address,
    write_function_ownership,
)
from tools.workflow.gen_class import classified_from_manifest, manifest_path
from tools.workflow.promote_from_autogen import (
    collect_autogen_blocks,
    parse_explicit_addresses,
    parse_ranges,
    split_blocks,
)
from tools.common import class_manifest as cm
from tools.common.thunk_names import ThunkResolver, load_thunk_map
from tools.workflow.shape_body import autogen_to_manual_block, shape_body


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--address",
        action="append",
        default=[],
        help="Function address to promote (hex). Repeat for multiple.",
    )
    parser.add_argument(
        "--range",
        action="append",
        default=[],
        help="Inclusive address range START:END (hex). Repeat for multiple.",
    )
    parser.add_argument("--target-cpp", required=True)
    parser.add_argument("--class", dest="cls", default="", help="Class name for shaping (default: infer from filename).")
    parser.add_argument("--module", default="IMPERIALISM")
    parser.add_argument("--autogen-dir", default="src/ghidra_autogen")
    parser.add_argument("--ownership-csv", default=DEFAULT_FUNCTION_OWNERSHIP_CSV)
    parser.add_argument("--ownership", default="manual")
    parser.add_argument("--ownership-note", default="promoted_shaped")
    parser.add_argument("--force-ownership", action="store_true")
    parser.add_argument(
        "--overwrite-existing",
        action="store_true",
        help="Replace already-present manual blocks at requested addresses.",
    )
    parser.add_argument(
        "--reorder",
        action="store_true",
        help="Run reorder_marked_functions on the target file after writing.",
    )
    return parser.parse_args()


def infer_class_from_cpp(path: Path) -> str:
    stem = path.stem
    if stem.startswith("T") or stem[0].isupper():
        return stem
    return ""


def slot_by_address(repo_root: Path, cls: str) -> dict[int, object]:
    mpath = manifest_path(repo_root, cls)
    if not mpath.is_file():
        return {}
    manifest = cm.load_manifest(mpath)
    slots = classified_from_manifest(manifest, repo_root)
    out: dict[int, object] = {}
    for slot in slots:
        if slot.target_addr:
            out[int(slot.target_addr, 16)] = slot
    return out


def shape_block(
    block: str,
    addr: int,
    cls: str,
    slot_map: dict[int, object],
    resolver: ThunkResolver | None,
) -> str:
    slot = slot_map.get(addr)
    if slot is not None:
        return shape_body(block, slot, cls, resolver)
    return autogen_to_manual_block(block, addr)


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    explicit = parse_explicit_addresses(args.address)
    ranges = parse_ranges(args.range)
    autogen_dir = resolve_repo_path(repo_root, args.autogen_dir)
    target_cpp = resolve_repo_path(repo_root, args.target_cpp)
    ownership_csv = resolve_repo_path(repo_root, args.ownership_csv)

    if not explicit and not ranges:
        raise SystemExit("No addresses requested. Use --address and/or --range.")

    if not autogen_dir.is_dir():
        raise SystemExit(f"Missing autogen directory: {autogen_dir}")

    available = collect_autogen_blocks(autogen_dir=autogen_dir, module=args.module)
    requested: set[int] = set(explicit)
    if ranges:
        for addr in available:
            for start, end in ranges:
                if start <= addr <= end:
                    requested.add(addr)
                    break

    addresses = sorted(requested)
    if not addresses:
        raise SystemExit("No functions found for the requested address/range selection.")

    missing = [addr for addr in explicit if addr not in available]
    if missing:
        missing_fmt = ", ".join(f"0x{addr:08X}" for addr in missing)
        raise SystemExit(f"Requested address(es) not found in autogen snapshot: {missing_fmt}")

    cls = args.cls.strip() or infer_class_from_cpp(target_cpp)
    slot_map = slot_by_address(repo_root, cls) if cls else {}
    resolver = ThunkResolver(load_thunk_map(repo_root / "config/thunk_map.csv"))

    ownership_entries = load_function_ownership(ownership_csv)
    target_cpp_rel = normalize_repo_relative_path(target_cpp, repo_root)
    ownership_conflicts: list[tuple[int, str]] = []
    for addr in addresses:
        existing = ownership_entries.get(addr)
        if existing is None:
            continue
        if existing.target_cpp == target_cpp_rel:
            continue
        if existing.ownership.lower() == "autogen":
            continue
        ownership_conflicts.append((addr, existing.target_cpp))

    if ownership_conflicts and not args.force_ownership:
        details = ", ".join(
            f"0x{addr:08X}->{owner}" for addr, owner in sorted(ownership_conflicts)
        )
        raise SystemExit(
            "Ownership conflict(s) detected. Use --force-ownership to overwrite: " + details
        )

    if target_cpp.exists():
        original = target_cpp.read_text(encoding="utf-8", errors="ignore")
        preamble, existing_blocks = split_blocks(original, args.module)
    else:
        preamble = (
            "// Manual decompilation file.\n"
            "// Use `just promote-shaped` or `just promote` to seed from autogen.\n\n"
        )
        existing_blocks = []

    merged: dict[int, str] = {addr: block for addr, block in existing_blocks}
    promoted_count = 0
    shaped_count = 0
    for addr in addresses:
        if addr in merged and not args.overwrite_existing:
            continue
        raw = available[addr]
        if slot_map.get(addr) is not None:
            merged[addr] = shape_block(raw, addr, cls, slot_map, resolver)
            shaped_count += 1
        else:
            merged[addr] = autogen_to_manual_block(raw, addr)
        if addr not in existing_blocks or args.overwrite_existing:
            if addr not in existing_blocks:
                promoted_count += 1

    ordered_addrs = sorted(merged.keys())
    body = "".join(merged[addr] for addr in ordered_addrs)
    output = preamble.rstrip() + "\n\n" + body

    target_cpp.parent.mkdir(parents=True, exist_ok=True)
    target_cpp.write_text(output, encoding="utf-8")

    ownership_updates = 0
    for addr in addresses:
        next_entry = FunctionOwnership(
            address=addr,
            target_cpp=target_cpp_rel,
            ownership=args.ownership,
            note=args.ownership_note,
        )
        if ownership_entries.get(addr) != next_entry:
            ownership_updates += 1
        ownership_entries[addr] = next_entry
    write_function_ownership(ownership_csv, ownership_entries)

    if args.reorder:
        from tools.workflow.reorder_marked_functions import reorder_file

        reorder_file(target_cpp, dry_run=False)

    print(f"Wrote {target_cpp}")
    print(f"Functions in file: {len(ordered_addrs)}")
    print(f"Newly promoted this run: {promoted_count}")
    print(f"Shaped with class manifest ({cls or 'none'}): {shaped_count}")
    print(f"Ownership updates: {ownership_updates} ({ownership_csv})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
