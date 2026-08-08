#!/usr/bin/env python3
"""Semantic gate for CRT/MFC library identity markers.

`symbols-integrity-gate` checks inventory *structure* (header, addresses, overlap)
but not whether library identities are semantically correct. This gate closes that
hole: every `// LIBRARY:` claim (and identity-bearing `// SYNTHETIC:` claim with a
linker symbol or prototype) must project exactly into generated `symbols.csv`.

Identity carriers live in manual source — primarily
`src/game/core/library_identities.cpp` and `CString.cpp`. Accepting an
object-matcher oracle hit means adding a marker block there.

It exists because provisional Ghidra names can stabilize into durable mistakes. For
example, `rand` at 0x005e83f0 has the MSVC LCG body `state*0x343fd + 0x269ec3`,
`(state>>16)&0x7fff`; a descriptive provisional name is not a substitute for `_rand`
identity and library ownership.

Failures:
  - an identity claim is not applied to symbols.csv (name/symbol/prototype/type drift);
  - an identity address is not owned as library/synthetic in the source model;
  - an identity claim is internally inconsistent (prototype does not declare the name);
  - a named `// SYNTHETIC:` claim's source_model name does not match symbols.csv.

Blank-name SYNTHETIC markers are ownership-only and are not name-checked.
Named SYNTHETIC validation uses `tools.source_model` — there is no second marker
parser.

Oracle-aware extras: a high-confidence unique library match must not be labeled
manual game code (unless allowlisted in `config/library_oracle_gamecode_allowlist.csv`).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.generate_symbols import identity_overlay_claims
from tools.source_model import build_model

DEFAULT_SYMBOLS = "build-msvc500/generated/symbols.csv"
DEFAULT_ORACLE = "build-msvc500/evidence/library/msvc500_library_oracle.csv"
DEFAULT_GAMECODE_ALLOWLIST = "config/library_oracle_gamecode_allowlist.csv"

APPLY_KINDS = {"unique", "unique-via-existing"}

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class IdentityCheck:
    address: int
    name: str
    symbol: str
    prototype: str
    kind: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--gamecode-allowlist", default=DEFAULT_GAMECODE_ALLOWLIST)
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
    return {
        address: "library" if claim.kind == "LIBRARY"
        else "generated" if claim.origin == "generated" else "manual"
        for address, claim in build_model(repo_root).functions.items()
    }


def index_ownership_full(repo_root: Path) -> dict[int, tuple[str, str]]:
    return {
        address: (
            claim.file,
            "library" if claim.kind == "LIBRARY"
            else "generated" if claim.origin == "generated" else "manual",
        )
        for address, claim in build_model(repo_root).functions.items()
    }


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
    """A high-confidence unique library match must not be labeled manual game code."""
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
            continue
        if address in allowlist:
            continue
        problems.append(
            f"0x{address:08x}: high-confidence library match {row.get('symbol')!r} "
            f"({row.get('member')}) is labeled game code in {owner[0]} (ownership={owner[1]}). "
            f"Move it to a // LIBRARY: marker "
            f"or acknowledge in {DEFAULT_GAMECODE_ALLOWLIST}."
        )
    return problems


def identity_checks(model) -> list[IdentityCheck]:
    return [
        IdentityCheck(
            address=claim.address,
            name=claim.name,
            symbol=claim.symbol,
            prototype=claim.prototype,
            kind=claim.kind,
        )
        for claim in identity_overlay_claims(model).values()
    ]


def check_override(
    ov: IdentityCheck, symbols: dict[int, dict[str, str]], ownership: dict[int, str]
) -> list[str]:
    problems: list[str] = []
    tag = f"0x{ov.address:08x} ({ov.name or ov.symbol or 'unnamed'})"

    if ov.prototype and ov.name and not prototype_declares_name(ov.prototype, ov.name):
        problems.append(
            f"{tag}: prototype {ov.prototype!r} does not declare the name {ov.name!r}"
        )

    row = symbols.get(ov.address)
    if row is None:
        problems.append(f"{tag}: no symbols.csv row (identity not applied)")
    else:
        if ov.name and (row.get("name") or "") != ov.name:
            problems.append(f"{tag}: symbols.csv name={row.get('name')!r} != {ov.name!r}")
        if ov.symbol and (row.get("symbol") or "") != ov.symbol:
            problems.append(
                f"{tag}: symbols.csv symbol={row.get('symbol')!r} != {ov.symbol!r}"
            )
        if ov.prototype and (row.get("prototype") or "") != ov.prototype:
            problems.append(
                f"{tag}: symbols.csv prototype={row.get('prototype')!r} != {ov.prototype!r}"
            )
        if (row.get("type") or "").strip().lower() != "function":
            problems.append(f"{tag}: symbols.csv type={row.get('type')!r} != 'function'")

    owner = ownership.get(ov.address)
    expected_owner = "manual" if ov.kind == "SYNTHETIC" else "library"
    if owner != expected_owner:
        problems.append(
            f"{tag}: ownership={owner!r} != {expected_owner!r} "
            f"(library identity claim missing from source model)"
        )

    return problems


def check_named_synthetic(
    claim, symbols: dict[int, dict[str, str]]
) -> list[str]:
    """Name-only SYNTHETIC markers must match the generated symbols.csv name."""
    if not claim.name:
        return []
    tag = f"0x{claim.address:08x} ({claim.name})"
    row = symbols.get(claim.address)
    if row is None:
        return [f"{tag}: no symbols.csv row for named SYNTHETIC claim"]
    actual = (row.get("name") or "").strip()
    if actual != claim.name:
        return [f"{tag}: symbols.csv name={actual!r} != {claim.name!r}"]
    return []


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    symbols_path = resolve_repo_path(repo_root, args.symbols)

    model = build_model(repo_root)
    overrides = identity_checks(model)
    applied_count = len(overrides)
    covered = {ov.address for ov in overrides}

    symbols = index_symbols(symbols_path)
    ownership = index_ownership(repo_root)

    problems: list[str] = []
    for ov in overrides:
        problems.extend(check_override(ov, symbols, ownership))

    named_synthetic = 0
    for claim in model.functions.values():
        if claim.kind != "SYNTHETIC" or not claim.name or claim.address in covered:
            continue
        named_synthetic += 1
        problems.extend(check_named_synthetic(claim, symbols))

    problems.extend(
        check_oracle_gamecode_conflicts(
            resolve_repo_path(repo_root, args.oracle),
            index_ownership_full(repo_root),
            load_gamecode_allowlist(resolve_repo_path(repo_root, args.gamecode_allowlist)),
        )
    )

    if problems:
        print("library-identity gate failed:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        f"library-identity gate passed: {applied_count} library identities and "
        f"{named_synthetic} named SYNTHETIC claims project exactly."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
