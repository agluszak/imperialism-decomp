#!/usr/bin/env python3
"""Stage 3: push source-owned names into the Ghidra DB so sync converges.

Source method names are canonical (they are what the binary compiles, and the
human's mental model); Ghidra names are provisional (Hard Rule 6). After a
`just sync-ghidra` the export carries Ghidra's names, which `merge_curated_symbols`
then has to re-overwrite by address every time — names churn but never converge.

This tool closes the loop in the other direction: for every address the *source*
owns (`function_ownership.csv` ownership=manual) it writes the canonical source
name into the Ghidra DB's function (creating the `Class::` namespace as needed),
leaving Ghidra-only addresses untouched. The next export then already produces the
matching name, so `sync-ghidra` converges instead of churning.

Canonical names are the *explicitly curated* source names — the manifest
curated.slots (`Class::method`) and config/function_name_overrides.csv (the
latter wins). It deliberately does NOT push the bulk of config/symbols.csv: those
names are mostly just the previous Ghidra export, so pushing them back would be a
no-op at best and a revert of newer DB names at worst. Backtick/synthetic names
(scalar deleting destructors) and non-identifier names are skipped.

Dry-run by default (prints the planned renames); pass --apply to open the project
writable and `program.save()`. Wired into `just sync-ghidra` before export and
runnable standalone as `just push-names`.

Usage:
  uv run python -m tools.ghidra.push_names_to_ghidra [--apply] [--limit N] [--verbose]
"""

from __future__ import annotations

import argparse
import re

import pyghidra

from tools.common import ghidra_env
from tools.common.name_overrides import parse_name_overrides, resolve_name_overrides_path
from tools.common.pipe_csv import normalize_hex, read_pipe_rows
from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__)
OWNERSHIP_PATH = REPO_ROOT / "config" / "function_ownership.csv"
NAME_OVERRIDES_PATH = resolve_name_overrides_path(REPO_ROOT, None)
SYMBOLS_PATH = REPO_ROOT / "config" / "symbols.csv"
DEFAULT_LIBRARY_START = 0x005E539C
DEFAULT_LIBRARY_END = 0x00626C7D

IDENT_RE = re.compile(r"^[A-Za-z_~][A-Za-z0-9_]*$")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Push source-owned names into the Ghidra DB.")
    p.add_argument("--apply", action="store_true", help="Write changes (default: dry-run).")
    p.add_argument("--limit", type=int, default=0, help="Process at most N renames (0 = all).")
    p.add_argument("--verbose", action="store_true", help="Print every planned rename.")
    p.add_argument(
        "--include-library-symbols",
        action="store_true",
        help="Also push symbols.csv names for ownership=library rows in the library range.",
    )
    p.add_argument(
        "--library-start",
        default=f"0x{DEFAULT_LIBRARY_START:08x}",
        help="Inclusive start for --include-library-symbols.",
    )
    p.add_argument(
        "--library-end",
        default=f"0x{DEFAULT_LIBRARY_END:08x}",
        help="Inclusive end for --include-library-symbols.",
    )
    return p.parse_args()


def parse_address(value: str) -> int:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return int(text, 16)


def owned_addresses(kind: str = "manual") -> set[int]:
    out: set[int] = set()
    for row in read_pipe_rows(OWNERSHIP_PATH):
        if (row.get("ownership") or "").strip() != kind:
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out.add(int(addr, 16))
    return out


def canonical_names(owned: set[int]) -> dict[int, str]:
    """address -> explicitly-curated source name, from function_name_overrides.csv.

    The bulk of symbols.csv is NOT a curation signal (it is mostly the previous
    export) and is intentionally excluded so a push can never revert a newer
    Ghidra DB name.
    """
    names: dict[int, str] = {}
    for addr, (name, _proto) in parse_name_overrides(NAME_OVERRIDES_PATH).items():
        if addr in owned and name:
            names[addr] = name
    return names


def library_symbol_names(owned: set[int], *, start: int, end: int) -> dict[int, str]:
    names: dict[int, str] = {}
    if not owned:
        return names
    for row in read_pipe_rows(SYMBOLS_PATH):
        if (row.get("type") or "").strip().lower() != "function":
            continue
        addr_text = normalize_hex((row.get("address") or "").strip())
        name = (row.get("name") or "").strip()
        if not addr_text or not name:
            continue
        addr = int(addr_text, 16)
        if addr in owned and start <= addr <= end:
            names[addr] = name
    return names


def split_qualified(qualified: str) -> tuple[list[str], str]:
    parts = qualified.split("::")
    return parts[:-1], parts[-1]


def run(program, args) -> dict:
    from ghidra.program.model.symbol import SourceType, SymbolUtilities
    from ghidra.util.exception import DuplicateNameException, InvalidInputException

    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    st = program.getSymbolTable()

    def A(x: int):
        return af.getAddress(x)

    def get_namespace(path: list[str]):
        parent = None
        for part in path:
            existing = st.getNamespace(part, parent)
            parent = existing if existing is not None else st.createClass(parent, part, SourceType.USER_DEFINED)
        return parent

    manual_owned = owned_addresses("manual")
    wanted: dict[int, tuple[str, str]] = {
        addr: (name, "manual") for addr, name in canonical_names(manual_owned).items()
    }
    library_owned_count = 0
    if args.include_library_symbols:
        start = parse_address(args.library_start)
        end = parse_address(args.library_end)
        if start > end:
            raise ValueError("--library-start must be <= --library-end")
        library_owned = owned_addresses("library")
        library_owned_count = len(library_owned)
        for addr, name in library_symbol_names(library_owned, start=start, end=end).items():
            wanted[addr] = (name, "library")

    stats = {"planned": 0, "applied": 0, "already": 0, "no_function": 0, "skipped_name": 0}
    changes: list[str] = []

    for addr in sorted(wanted):
        desired_qualified, name_source = wanted[addr]
        ns_path, simple = split_qualified(desired_qualified)
        if name_source != "library" and not IDENT_RE.match(simple):
            stats["skipped_name"] += 1
            continue
        if name_source == "library" and re.search(r"[`\s]", desired_qualified):
            # Ghidra rejects symbol names with spaces/backticks (MFC "`scalar
            # deleting dtor'" spellings, descriptive curated names); they can
            # never be pushed as-is, so don't re-attempt + fail on every sync.
            stats["skipped_name"] += 1
            continue
        fn = fm.getFunctionAt(A(addr))
        if fn is None:
            stats["no_function"] += 1
            continue
        current = fn.getName(True)
        if current == desired_qualified:
            stats["already"] += 1
            continue
        stats["planned"] += 1
        if args.limit and stats["planned"] > args.limit:
            stats["planned"] -= 1
            break
        if args.verbose or not args.apply:
            changes.append(f"  0x{addr:08x}: {current} -> {desired_qualified}")
        if args.apply:
            try:
                if name_source == "library":
                    fn.setName(desired_qualified, SourceType.USER_DEFINED)
                else:
                    ns = get_namespace(ns_path) if ns_path else None
                    if ns is not None:
                        fn.setParentNamespace(ns)
                    fn.setName(simple, SourceType.USER_DEFINED)
                stats["applied"] += 1
            except DuplicateNameException:
                if name_source != "library":
                    changes.append(f"  !! 0x{addr:08x} -> {desired_qualified} failed: duplicate")
                    continue
                try:
                    fallback = str(SymbolUtilities.getAddressAppendedName(desired_qualified, fn.getEntryPoint()))
                    fn.setName(fallback, SourceType.USER_DEFINED)
                    stats["applied"] += 1
                    changes.append(f"  !! 0x{addr:08x}: duplicate, used {fallback}")
                except (DuplicateNameException, InvalidInputException) as exc:
                    changes.append(f"  !! 0x{addr:08x} -> {desired_qualified} failed: {exc}")
            except Exception as exc:  # noqa: BLE001
                changes.append(f"  !! 0x{addr:08x} -> {desired_qualified} failed: {exc}")

    return {
        "stats": stats,
        "changes": changes,
        "manual_owned": len(manual_owned),
        "library_owned": library_owned_count,
        "wanted": len(wanted),
    }


def main() -> int:
    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        if args.apply:
            txid = program.startTransaction("push source-owned names")
        result = run(program, args)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("push source-owned names", pyghidra.task_monitor())

        s = result["stats"]
        mode = "APPLIED" if args.apply else "DRY RUN"
        for line in result["changes"][:4000]:
            print(line)
        print(
            f"\n[{mode}] manual_owned={result['manual_owned']} "
            f"library_owned={result['library_owned']} with_name={result['wanted']} "
            f"planned={s['planned']} applied={s['applied']} already_matching={s['already']} "
            f"no_function={s['no_function']} skipped_name={s['skipped_name']}"
        )
        if not args.apply:
            print("Re-run with --apply to write these names into the Ghidra DB.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
