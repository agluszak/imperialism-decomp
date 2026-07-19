#!/usr/bin/env python3
"""Project reviewed MSVC500 library-identity overrides into the derived artifacts.

`config/msvc500_library_overrides.csv` is the reviewed authority for confirmed
CRT/MFC library functions that Ghidra FID missed or mislabeled (the canonical
example is `rand` at 0x005e83f0, which FID knows as `_rand` in `rand.obj` but
skips in the executable because the body is below its length/score threshold, so
Ghidra keeps the invented behavioural name `GenerateThreadLocalRandom15`).

A FID miss is invisible to `apply_msvc500_library_region.py` (it only consumes
functions the FID query returned), so these identities need a separate, always-run
projection step. This module is that step. It is idempotent and safe to re-run.

Precedence (highest first): reviewed override > FID match > existing curated
identity > provisional Ghidra identity. This tool owns the top tier: it writes
name/symbol/prototype/provenance into `config/original_entities.csv` (the curated merge in
the refresh preserves those columns by address) and ensures a `// LIBRARY:`
marker exists (markers are the ownership authority).

A marker is only *added* when no `// LIBRARY:` marker already exists for the
address anywhere in the source tree, so overrides that merely correct a rotten
prototype on an already-owned FID row (e.g. `srand`, `memmove`) never introduce a
duplicate `// FUNCTION:`/`// LIBRARY:` marker (marker Hard Rule 4).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows, read_pipe_table
from tools.common.repo import (
    normalize_repo_relative_path,
    repo_root_from_file,
    resolve_repo_path,
)
from tools.ghidra.merge_curated_symbols import write_symbols_csv
from tools.mfc.apply_msvc500_library_region import (
    collect_manual_source_references,
    collect_source_markers,
)

DEFAULT_OVERRIDES = "config/msvc500_library_overrides.csv"
DEFAULT_SYMBOLS = "config/original_entities.csv"
DEFAULT_MARKERS = "src/game/library_msvc500_overrides.cpp"
PROVENANCE = "msvc500_library_override"

REQUIRED_COLUMNS = (
    "address",
    "name",
    "symbol",
    "prototype",
    "library_family",
    "object_member",
    "evidence",
)


@dataclass(frozen=True)
class LibraryOverride:
    address: int
    name: str
    symbol: str
    prototype: str
    library_family: str
    object_member: str
    evidence: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply reviewed MSVC500 library-identity overrides to symbols.csv + markers."
    )
    parser.add_argument("--overrides", default=DEFAULT_OVERRIDES)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--markers", default=DEFAULT_MARKERS)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report what would change and exit non-zero if anything is stale; write nothing.",
    )
    return parser.parse_args()


def load_overrides(path: Path) -> list[LibraryOverride]:
    if not path.is_file():
        raise FileNotFoundError(path)
    rows = read_pipe_rows(path)
    overrides: list[LibraryOverride] = []
    seen: set[int] = set()
    for row in rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        for column in REQUIRED_COLUMNS:
            if column not in row:
                raise SystemExit(
                    f"{path}: missing required column '{column}'. Header must be: "
                    f"{'|'.join(REQUIRED_COLUMNS)}"
                )
        address = parse_hex_address(addr_text)
        if address in seen:
            raise SystemExit(f"{path}: duplicate override for 0x{address:08x}")
        seen.add(address)
        name = (row.get("name") or "").strip()
        symbol = (row.get("symbol") or "").strip()
        prototype = (row.get("prototype") or "").strip()
        if not name or not symbol or not prototype:
            raise SystemExit(
                f"{path}: 0x{address:08x} needs non-empty name, symbol and prototype."
            )
        overrides.append(
            LibraryOverride(
                address=address,
                name=name,
                symbol=symbol,
                prototype=prototype,
                library_family=(row.get("library_family") or "").strip(),
                object_member=(row.get("object_member") or "").strip(),
                evidence=(row.get("evidence") or "").strip(),
            )
        )
    overrides.sort(key=lambda o: o.address)
    return overrides


def apply_symbols(
    symbols_path: Path, overrides: list[LibraryOverride]
) -> tuple[list[str], bool]:
    """Return the human-readable change list and whether symbols.csv was modified."""
    fieldnames, rows = read_pipe_table(symbols_path)
    for column in ("symbol", "provenance"):
        if column not in fieldnames:
            fieldnames.append(column)
    by_addr: dict[int, dict[str, str]] = {}
    for row in rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            by_addr[int(addr_text, 16)] = row
        except ValueError:
            continue

    changes: list[str] = []
    for ov in overrides:
        row = by_addr.get(ov.address)
        if row is None:
            row = {
                "address": format(ov.address, "x"),
                "name": ov.name,
                "symbol": ov.symbol,
                "size": "",
                "type": "function",
                "prototype": ov.prototype,
                "provenance": PROVENANCE,
            }
            rows.append(row)
            changes.append(f"0x{ov.address:08x} add row name={ov.name} symbol={ov.symbol}")
            continue
        want = {
            "name": ov.name,
            "symbol": ov.symbol,
            "prototype": ov.prototype,
            "type": "function",
            "provenance": PROVENANCE,
        }
        for key, value in want.items():
            if (row.get(key) or "") != value:
                changes.append(
                    f"0x{ov.address:08x} {key}: {row.get(key) or ''!r} -> {value!r}"
                )
                row[key] = value

    if changes:
        rows.sort(key=lambda row: int((row.get("address") or "0"), 16))
        write_symbols_csv(symbols_path, fieldnames, rows)
    return changes, bool(changes)


def render_marker_file(
    overrides: list[LibraryOverride], addresses: list[int], *, target: str
) -> str:
    by_addr = {o.address: o for o in overrides}
    lines = [
        "// AUTO-GENERATED by tools/mfc/apply_library_overrides.py -- do not hand-edit.",
        "// Reviewed MSVC500 library-identity overrides"
        " (config/msvc500_library_overrides.csv):",
        "// confirmed CRT/MFC library functions FID missed. Ownership derives from",
        "// these // LIBRARY: markers. Edit the CSV, not this file.",
        "",
        "#if 0",
    ]
    for address in sorted(addresses):
        ov = by_addr[address]
        lines.append(f"// LIBRARY: {target} 0x{address:08x}")
        lines.append(f"// {ov.symbol}")
        lines.append("")
    lines.append("#endif")
    return "\n".join(lines) + "\n"


def apply_markers(
    marker_path: Path,
    overrides: list[LibraryOverride],
    existing_markers: dict[int, object],
    *,
    marker_rel: str,
    target: str,
) -> tuple[list[str], bool]:
    """Ensure a // LIBRARY: marker exists for override addresses that lack one.

    Addresses that already carry a LIBRARY marker in another file (a prior FID
    marker) are left alone — those overrides only correct symbols.csv metadata.
    """
    owned: list[int] = []
    changes: list[str] = []
    for ov in overrides:
        marker = existing_markers.get(ov.address)
        marker_path_of = getattr(marker, "path", None)
        marker_kind = getattr(marker, "kind", None)
        if marker is None or (marker_kind == "LIBRARY" and marker_path_of == marker_rel):
            # Either no marker yet, or a marker this file already owns.
            owned.append(ov.address)
            if marker is None:
                changes.append(f"0x{ov.address:08x} add // LIBRARY: marker")
        elif marker_kind == "LIBRARY":
            # A LIBRARY marker exists elsewhere (e.g. the FID file) — metadata-only override.
            continue
        else:
            raise SystemExit(
                f"0x{ov.address:08x} already has a // {marker_kind}: marker in "
                f"{marker_path_of}; a reviewed library override must not collide with a "
                f"non-library marker. Resolve the ownership conflict first."
            )

    desired = render_marker_file(overrides, owned, target=target)
    current = marker_path.read_text(encoding="utf-8") if marker_path.is_file() else ""
    if desired != current:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(desired, encoding="utf-8")
        if not changes:
            changes.append(f"rewrote {marker_rel}")
    return changes, bool(changes)


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    overrides_path = resolve_repo_path(repo_root, args.overrides)
    symbols_path = resolve_repo_path(repo_root, args.symbols)
    marker_path = resolve_repo_path(repo_root, args.markers)
    marker_rel = normalize_repo_relative_path(marker_path, repo_root)

    overrides = load_overrides(overrides_path)
    if not overrides:
        print(f"no overrides in {overrides_path}; nothing to do.")
        return 0

    existing_markers = collect_source_markers(repo_root, args.target)

    if args.check:
        # Dry-run: compute changes without writing. Reuse the appliers against copies.
        symbol_changes, _ = _dry_run_symbols(symbols_path, overrides)
        marker_changes = _dry_run_markers(
            marker_path, overrides, existing_markers, marker_rel=marker_rel, target=args.target
        )
        changes = symbol_changes + marker_changes
        if changes:
            print("library overrides are not applied (run `just apply-library-overrides`):")
            for change in changes:
                print(f"  - {change}")
            return 1
        print(f"library overrides applied and current ({len(overrides)} entries).")
        return 0

    # Callsite-orphan guard: an override that newly converts an address to library
    # removes its autogen stub. If manual source still calls it by its old invented
    # name, the link breaks (rand's `GenerateThreadLocalRandom15` callsites did
    # exactly this). Warn loudly so those callsites get migrated to the real symbol.
    orphan_warnings = _callsite_orphan_warnings(
        repo_root, overrides, existing_markers, symbols_path, marker_rel
    )

    symbol_changes, _ = apply_symbols(symbols_path, overrides)
    marker_changes, _ = apply_markers(
        marker_path, overrides, existing_markers, marker_rel=marker_rel, target=args.target
    )
    print(
        f"applied {len(overrides)} library overrides: "
        f"symbols_changes={len(symbol_changes)} marker_changes={len(marker_changes)}"
    )
    for change in symbol_changes + marker_changes:
        print(f"  - {change}")
    for warning in orphan_warnings:
        print(f"  WARNING: {warning}")
    return 0


def _callsite_orphan_warnings(
    repo_root: Path,
    overrides: list[LibraryOverride],
    existing_markers: dict[int, object],
    symbols_path: Path,
    marker_rel: str,
) -> list[str]:
    # Only overrides that will *newly* get a library marker here can orphan a stub.
    newly_owned = [
        ov for ov in overrides if existing_markers.get(ov.address) is None
    ]
    if not newly_owned:
        return []
    old_names: dict[int, str] = {}
    _fieldnames, rows = read_pipe_table(symbols_path)
    by_addr = {int(r["address"], 16): r for r in rows if (r.get("address") or "").strip()}
    for ov in newly_owned:
        row = by_addr.get(ov.address)
        if row and (row.get("name") or "") not in ("", ov.name):
            old_names[ov.address] = row["name"]
    referenced = collect_manual_source_references(
        repo_root, set(old_names.values()), marker_rel=marker_rel
    )
    warnings: list[str] = []
    for addr, old in old_names.items():
        if old in referenced:
            warnings.append(
                f"0x{addr:08x}: manual source still calls {old!r}; migrate those "
                f"callsites to the real symbol or the link will fail (stub removed)."
            )
    return warnings


def _dry_run_symbols(
    symbols_path: Path, overrides: list[LibraryOverride]
) -> tuple[list[str], bool]:
    fieldnames, rows = read_pipe_table(symbols_path)
    by_addr: dict[int, dict[str, str]] = {}
    for row in rows:
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            by_addr[int(addr_text, 16)] = row
        except ValueError:
            continue
    changes: list[str] = []
    has_symbol = "symbol" in fieldnames
    for ov in overrides:
        row = by_addr.get(ov.address)
        if row is None:
            changes.append(f"0x{ov.address:08x} add row name={ov.name} symbol={ov.symbol}")
            continue
        want = {
            "name": ov.name,
            "symbol": ov.symbol if has_symbol else "",
            "prototype": ov.prototype,
            "type": "function",
            "provenance": PROVENANCE,
        }
        for key, value in want.items():
            if (row.get(key) or "") != value:
                changes.append(f"0x{ov.address:08x} {key} stale")
    return changes, bool(changes)


def _dry_run_markers(
    marker_path: Path,
    overrides: list[LibraryOverride],
    existing_markers: dict[int, object],
    *,
    marker_rel: str,
    target: str,
) -> list[str]:
    owned: list[int] = []
    changes: list[str] = []
    for ov in overrides:
        marker = existing_markers.get(ov.address)
        marker_path_of = getattr(marker, "path", None)
        marker_kind = getattr(marker, "kind", None)
        if marker is None or (marker_kind == "LIBRARY" and marker_path_of == marker_rel):
            owned.append(ov.address)
            if marker is None:
                changes.append(f"0x{ov.address:08x} missing // LIBRARY: marker")
    desired = render_marker_file(overrides, owned, target=target)
    current = marker_path.read_text(encoding="utf-8") if marker_path.is_file() else ""
    if desired != current and not changes:
        changes.append(f"{marker_rel} out of date")
    return changes


if __name__ == "__main__":
    raise SystemExit(main())
