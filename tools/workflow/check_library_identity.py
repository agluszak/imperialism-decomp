#!/usr/bin/env python3
"""Semantic gate for reviewed MSVC500 library identities.

`symbols-integrity-gate` checks CSV *structure* (header, addresses, overlap) but
not whether library identities are semantically correct. This gate closes that
hole for the reviewed set: every row in `config/msvc500_library_overrides.csv`
must be faithfully projected into `config/original_entities.csv` and `// LIBRARY:` markers.

It exists because the sync pipeline stabilizes a FID miss into a durable mistake:
a function FID skipped (e.g. `rand` at 0x005e83f0, whose body is the MSVC LCG
`state*0x343fd + 0x269ec3`, `(state>>16)&0x7fff`) keeps its invented Ghidra name
`GenerateThreadLocalRandom15` forever, with no `_rand` symbol and no library
ownership. The reviewed override layer fixes such rows; this gate makes the fix
un-revertible.

Failures (for the reviewed override set):
  - an override is not applied to symbols.csv (name/symbol/prototype/type drift);
  - an override address has no `// LIBRARY:` marker;
  - an override row is internally inconsistent (missing symbol, or the friendly
    name is absent from the prototype);
  - the number of applied overrides dropped below the ratchet baseline (silent
    removal of a confirmed library identity).

`--write-baseline` records the current applied-override count.

The broader checks the object-matcher oracle enables (every library row carries a
symbol; a confirmed oracle match missing from the markers; a high-confidence
library match classified as game code) are deferred until that oracle lands; see
`config/msvc500_library_overrides.csv` header and docs/reference.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.mfc.apply_library_overrides import LibraryOverride, load_overrides

DEFAULT_OVERRIDES = "config/msvc500_library_overrides.csv"
DEFAULT_SYMBOLS = "config/original_entities.csv"
DEFAULT_BASELINE = "config/library_identity_gate_baseline.json"
DEFAULT_ORACLE = "config/msvc500_library_oracle.csv"
DEFAULT_GAMECODE_ALLOWLIST = "config/library_oracle_gamecode_allowlist.csv"

APPLY_KINDS = {"unique", "unique-via-existing"}

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overrides", default=DEFAULT_OVERRIDES)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--gamecode-allowlist", default=DEFAULT_GAMECODE_ALLOWLIST)
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Record the current applied-override count as the baseline and exit.",
    )
    return parser.parse_args()


def prototype_declares_name(prototype: str, name: str) -> bool:
    """True if the friendly name (its last ::-component) is a token in the prototype.

    `int __cdecl rand(void)` declares `rand`; `void * __cdecl memmove(...)` declares
    `memmove`; `CObject::operator delete` -> `operator delete` is handled loosely by
    checking the trailing identifier.
    """
    leaf = name.rsplit("::", 1)[-1].strip()
    # operator names and dtors are not plain identifiers; accept them structurally.
    if not IDENT_RE.fullmatch(leaf):
        return True
    return leaf in set(IDENT_RE.findall(prototype))


def index_symbols(symbols_path: Path) -> dict[int, dict[str, str]]:
    out: dict[int, dict[str, str]] = {}
    for row in read_pipe_rows(symbols_path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            out[int(addr_text, 16)] = row
        except ValueError:
            continue
    return out


def index_ownership(repo_root: Path) -> dict[int, str]:
    from tools.source_index import ownership_kind, ownership_view

    return {a: ownership_kind(c.kind) for a, c in ownership_view(repo_root).items()}


def index_ownership_full(repo_root: Path) -> dict[int, tuple[str, str]]:
    from tools.source_index import ownership_kind, ownership_view

    return {a: (c.file, ownership_kind(c.kind))
            for a, c in ownership_view(repo_root).items()}


def load_gamecode_allowlist(path: Path) -> set[int]:
    if not path.is_file():
        return set()
    out: set[int] = set()
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            out.add(int(addr_text, 16))
        except ValueError:
            continue
    return out


def check_oracle_gamecode_conflicts(
    oracle_path: Path, ownership_full: dict[int, tuple[str, str]], allowlist: set[int]
) -> list[str]:
    """A high-confidence unique library match must not be labeled manual game code.

    This is the mechanical form of 'unmatched-by-FID != game code': the object
    matcher independently proves the byte identity, so a confident unique match
    owned by a game .cpp (e.g. libcmt float internals ported as bignum96_math.cpp)
    is a mislabel. Pre-existing ones are acknowledged in the allowlist; a NEW one
    (regression) fails the gate.
    """
    if not oracle_path.is_file():
        return []
    problems: list[str] = []
    for row in read_pipe_rows(oracle_path):
        if (row.get("match_kind") or "") not in APPLY_KINDS:
            continue
        if (row.get("confidence") or "") != "high":
            continue
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            address = int(addr_text, 16)
        except ValueError:
            continue
        owner = ownership_full.get(address)
        if owner is None or owner[1] == "library":
            continue  # unowned or already library — not a game-code mislabel
        if address in allowlist:
            continue
        problems.append(
            f"0x{address:08x}: high-confidence library match {row.get('symbol')!r} "
            f"({row.get('member')}) is labeled game code in {owner[0]} (ownership={owner[1]}). "
            f"A FID/heuristic miss is not evidence of game ownership — move it to library, "
            f"or acknowledge in {DEFAULT_GAMECODE_ALLOWLIST}."
        )
    return problems


def check_override(
    ov: LibraryOverride, symbols: dict[int, dict[str, str]], ownership: dict[int, str]
) -> list[str]:
    problems: list[str] = []
    tag = f"0x{ov.address:08x} ({ov.name})"

    if not ov.symbol:
        problems.append(f"{tag}: reviewed override has no linker symbol")
    if not prototype_declares_name(ov.prototype, ov.name):
        problems.append(
            f"{tag}: prototype {ov.prototype!r} does not declare the name {ov.name!r}"
        )

    row = symbols.get(ov.address)
    if row is None:
        problems.append(f"{tag}: no symbols.csv row (override not applied)")
    else:
        if (row.get("name") or "") != ov.name:
            problems.append(f"{tag}: symbols.csv name={row.get('name')!r} != {ov.name!r}")
        if (row.get("symbol") or "") != ov.symbol:
            problems.append(
                f"{tag}: symbols.csv symbol={row.get('symbol')!r} != {ov.symbol!r}"
            )
        if (row.get("prototype") or "") != ov.prototype:
            problems.append(
                f"{tag}: symbols.csv prototype={row.get('prototype')!r} != {ov.prototype!r}"
            )
        if (row.get("type") or "").strip().lower() != "function":
            problems.append(f"{tag}: symbols.csv type={row.get('type')!r} != 'function'")

    owner = ownership.get(ov.address)
    if owner != "library":
        problems.append(f"{tag}: ownership={owner!r} != 'library' (marker missing?)")

    return problems


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    overrides_path = resolve_repo_path(repo_root, args.overrides)
    symbols_path = resolve_repo_path(repo_root, args.symbols)
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    overrides = load_overrides(overrides_path)
    applied_count = len(overrides)

    if args.write_baseline:
        baseline_path.write_text(
            json.dumps({"applied_override_count": applied_count}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.baseline}: applied_override_count={applied_count}")
        return 0

    symbols = index_symbols(symbols_path)
    ownership = index_ownership(repo_root)

    problems: list[str] = []
    for ov in overrides:
        problems.extend(check_override(ov, symbols, ownership))

    # Oracle-aware check: confident unique library matches must not be game code.
    problems.extend(
        check_oracle_gamecode_conflicts(
            resolve_repo_path(repo_root, args.oracle),
            index_ownership_full(repo_root),
            load_gamecode_allowlist(resolve_repo_path(repo_root, args.gamecode_allowlist)),
        )
    )

    baseline_count = 0
    if baseline_path.is_file():
        baseline_count = int(json.loads(baseline_path.read_text()).get("applied_override_count", 0))
    if applied_count < baseline_count:
        problems.append(
            f"applied override count dropped {baseline_count} -> {applied_count}: a "
            f"confirmed library identity was removed. Restore it or, if intentional, "
            f"run `just library-identity-gate-update`."
        )

    if problems:
        print("library-identity gate failed:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        f"library-identity gate passed: {applied_count} reviewed overrides applied "
        f"(baseline {baseline_count})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
