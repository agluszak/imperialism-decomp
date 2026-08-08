#!/usr/bin/env python3
"""One-shot library-identity diagnostic for a single address.

    just library-identify 0x005e83f0

Aggregates every maintained identity signal for an address — current curated
symbols.csv row, ownership, source LIBRARY/SYNTHETIC identity marker, and the
relocation-masked object match — into a single verdict. Run this before naming
any function in the MSVC/MFC library range, or any CRT-shaped callee elsewhere.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.generate_symbols import identity_overlay_claims
from tools.source_model import build_model

DEFAULT_SYMBOLS = "config/original_entities.csv"
DEFAULT_ORACLE = "build-msvc500/evidence/library/msvc500_library_oracle.csv"

# Dense MFC/CRT library region recovered from the retail executable.
LIBRARY_RANGE = (0x005E539C, 0x00626C7D)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="Function address, e.g. 0x005e83f0")
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    return parser.parse_args()


def _row_for_address(path: Path, address: int) -> dict[str, str] | None:
    if not path.is_file():
        return None
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            if int(addr_text, 16) == address:
                return row
        except ValueError:
            continue
    return None


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    address = parse_hex_address(args.address)

    symbols_row = _row_for_address(resolve_repo_path(repo_root, args.symbols), address)
    model = build_model(repo_root)
    claim = model.functions.get(address)
    ownership_row = (
        {
            "ownership": "library" if claim.kind == "LIBRARY" else (
                "generated" if claim.origin == "generated" else "manual"
            ),
            "target_cpp": claim.file,
        }
        if claim else None
    )
    oracle_row = _row_for_address(resolve_repo_path(repo_root, args.oracle), address)
    identity = identity_overlay_claims(model).get(address)

    name = (symbols_row or {}).get("name", "") or "<none>"
    symbol = (symbols_row or {}).get("symbol", "") or "<missing>"
    prototype = (symbols_row or {}).get("prototype", "") or "<none>"
    ownership = (ownership_row or {}).get("ownership", "") or "unowned/autogen"
    in_dense = LIBRARY_RANGE[0] <= address <= LIBRARY_RANGE[1]

    print(f"Address:             0x{address:08x}")
    print(f"Current name:        {name}")
    print(f"Current symbol:      {symbol}")
    print(f"Current prototype:   {prototype}")
    print(f"Ownership:           {ownership}")
    print(f"In dense lib range:  {'yes' if in_dense else 'no'} "
          f"(0x{LIBRARY_RANGE[0]:x}-0x{LIBRARY_RANGE[1]:x})")
    print()

    if oracle_row is not None:
        print(f"Object matcher:      {oracle_row.get('match_kind', '?')} -> "
              f"{oracle_row.get('symbol', '?')} "
              f"[{oracle_row.get('library', '?')}/{oracle_row.get('member', '?')} "
              f"confidence={oracle_row.get('confidence', '?')} "
              f"candidates={oracle_row.get('candidate_count', '?')}]")
    else:
        print("Object matcher:      not available "
              "(build-msvc500/evidence/library/msvc500_library_oracle.csv not built yet)")

    if identity is not None:
        print()
        print(f"Identity marker:     {identity.kind} in {identity.file}")
        print(f"  name:              {identity.name or '<none>'}")
        print(f"  symbol:            {identity.symbol or '<none>'}")
        print(f"  prototype:         {identity.prototype or '<none>'}")

    print()
    if identity is not None and identity.kind == "LIBRARY":
        verdict = "confirmed library function (source LIBRARY marker)"
    elif oracle_row is not None and (oracle_row.get("match_kind") or "").startswith("unique"):
        verdict = f"confirmed library function (unique object match: {oracle_row.get('symbol')})"
    elif ownership == "library":
        verdict = "library function (marker owned)"
    elif in_dense:
        verdict = (
            "UNOWNED inside the dense library range — do NOT behaviourally name. "
            "Add a // LIBRARY: marker in src/game/core/library_identities.cpp "
            "or run the object matcher."
        )
    else:
        verdict = (
            "not identified as library. If the body is CRT/MFC-shaped (LCG, ctype, "
            "string/mem helper, MFC macro), do NOT invent a game name — add a "
            "// LIBRARY: marker in src/game/core/library_identities.cpp."
        )
    print(f"Verdict:             {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
