#!/usr/bin/env python3
"""Relocation-masked MSVC500 static-library identity oracle.

FID is heuristic (length/score thresholds), so it silently misses small or
aliased CRT/MFC functions and mislabels others. This builds an *authoritative*
identity oracle by matching the linked executable's function bytes against the
exact object members of the vendored `libcmt.lib` / `nafxcw.lib`, normalized so
that linker-assigned addresses don't matter:

  1. Extract every external function from every object member (tools.mfc.coff).
  2. Mask the bytes covered by each function's relocations (call/jmp targets,
     absolute data refs) and trim trailing alignment padding -> a normal form.
  3. For each executable function (config/symbols.csv), read its bytes, mask at a
     candidate's relocation offsets, and compare. An exact-size, exact-masked
     match is a confident identity independent of where the linker placed things.

Duplicate normal forms (byte-identical library functions) are resolved with
secondary evidence — the symbol the address already carries — before falling back
to a review queue. Output: config/msvc500_library_oracle.csv with
address|name|symbol|prototype|library|member|match_kind|confidence|candidate_count.

Unique matches are safe to apply automatically (see apply_library_oracle.py);
ambiguous rows stay a review queue rather than receiving an invented name.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from reccmp.cvdump.demangler import msvc_demangle

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.mfc.coff import LibraryFunction, mask_bytes, parse_library, _trim_padding
from tools.mfc.pe_image import PEImage

DEFAULT_LIBS = [
    ("libcmt", "vendor/msvc500/lib/libcmt.lib"),
    ("nafxcw", "vendor/msvc500/lib/nafxcw.lib"),
]
DEFAULT_SYMBOLS = "config/symbols.csv"
DEFAULT_OUT = "config/msvc500_library_oracle.csv"

# Below this size a full masked match is not discriminative enough to trust
# blindly (many tiny thunks share a normal form); such matches are still recorded
# but never marked confidence=high unless the symbol already agrees.
#
# Note on the masking blind spot: relocation masking zeroes address operands, so a
# vtable-pointer store (`mov [ecx], <reloc>` -> `C7 01 00000000`) is byte-identical
# to a zero-immediate store (`field = 0` -> `C7 01 00000000`). A tiny game function
# (`field@X = 0; ret`) can therefore collide with a trivial library method
# (CCmdTarget::EnableAggregation, exception::exception). A masked-signal (non-zero
# byte count) threshold does NOT separate these: a real `__fpmath` (23B, 7 non-zero)
# has *less* signal than a coincidental `exception::exception` match (17B, 12
# non-zero). So such collisions are resolved by human review + the game-code
# allowlist, not a byte heuristic. Only cross-address duplication (below) is demoted
# automatically.
MIN_CONFIDENT_SIZE = 8


@dataclass(frozen=True)
class OracleMatch:
    address: int
    name: str
    symbol: str
    prototype: str
    library: str
    member: str
    match_kind: str  # unique | unique-via-existing | ambiguous
    confidence: str  # high | review
    candidate_count: int


_CALL_CONVENTIONS = ("__thiscall", "__cdecl", "__stdcall", "__fastcall", "__clrcall")


def friendly_name_and_prototype(symbol: str) -> tuple[str, str]:
    """Return (qualified friendly name, prototype) for a decorated or C linker symbol.

    C++: `?AddBitmap@CToolBarCtrl@@...` -> ("CToolBarCtrl::AddBitmap", full sig).
    C:   `_atexit` -> ("atexit", "").  `__ftol` -> ("_ftol", "").
    """
    if symbol.startswith("?"):
        demangled = msvc_demangle(symbol) or ""
        if not demangled:
            return symbol, ""
        # The qualified name is what follows the calling-convention token, up to the
        # parameter list. operator names keep their spaces (operator delete); a
        # function-pointer return type has parens of its own, so cut at the first '('.
        idx = max((demangled.rfind(cc) for cc in _CALL_CONVENTIONS), default=-1)
        tail = demangled[idx + len(demangled[idx:].split(None, 1)[0]) :] if idx >= 0 else demangled
        name = tail.split("(", 1)[0].strip()
        leaf = name.split("::")[-1].replace("operator ", "operator")
        if not name or any(ch in name for ch in "*()") or " " in leaf:
            # Function-pointer return types and other unusual shapes defeat the
            # positional parse; fall back to the leaf identifier from the symbol.
            m = re.match(r"\?\??(~?[A-Za-z_][A-Za-z0-9_]*)@", symbol)
            name = m.group(1) if m else symbol
        return (name or symbol), demangled
    # C symbol: MSVC prepends a single underscore to __cdecl C names.
    return (symbol[1:] if symbol.startswith("_") else symbol), ""


class LibraryIndex:
    """size -> reloc_offsets -> masked_bytes -> [LibraryFunction]."""

    def __init__(self) -> None:
        self._index: dict[int, dict[tuple[int, ...], dict[bytes, list[LibraryFunction]]]] = (
            defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        )
        self.library_of: dict[str, str] = {}

    def add(self, library: str, func: LibraryFunction) -> None:
        self._index[func.size][func.reloc_offsets][func.masked()].append(func)
        self.library_of.setdefault(func.symbol, library)

    def match(self, size: int, body: bytes) -> list[LibraryFunction]:
        out: list[LibraryFunction] = []
        for reloc_offsets, masked_map in self._index.get(size, {}).items():
            hit = masked_map.get(mask_bytes(body, reloc_offsets))
            if hit:
                out.extend(hit)
        return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=None, help="Original executable (default: $ORIGINAL_BINARY or orig/Imperialism.exe)")
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--lib", action="append", default=[], help="extra family=path lib")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def resolve_binary(repo_root: Path, requested: str | None) -> Path:
    import os

    for candidate in (requested, os.environ.get("ORIGINAL_BINARY"), "orig/Imperialism.exe"):
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute():
            path = repo_root / candidate
        if path.is_file():
            return path
    raise SystemExit(
        "original binary not found; set ORIGINAL_BINARY or pass --binary "
        "(needed to read executable function bytes)."
    )


def build_index(repo_root: Path, libs: list[tuple[str, str]], quiet: bool) -> LibraryIndex:
    index = LibraryIndex()
    for family, rel in libs:
        path = resolve_repo_path(repo_root, rel)
        if not path.is_file():
            raise SystemExit(f"library not found: {path} (vendor it first)")
        funcs = parse_library(path)
        for func in funcs:
            index.add(family, func)
        if not quiet:
            print(f"  indexed {len(funcs)} functions from {family} ({rel})")
    return index


def load_exe_functions(symbols_path: Path) -> list[tuple[int, int, str]]:
    """Return (address, size, current_name) for every sized function row."""
    out: list[tuple[int, int, str]] = []
    for row in read_pipe_rows(symbols_path):
        if (row.get("type") or "").strip().lower() != "function":
            continue
        addr_text = (row.get("address") or "").strip()
        size_text = (row.get("size") or "").strip()
        if not addr_text or not size_text:
            continue
        try:
            address = int(addr_text, 16)
            size = int(size_text)
        except ValueError:
            continue
        if size <= 0:
            continue
        out.append((address, size, (row.get("symbol") or "").strip()))
    return out


def classify(
    address: int,
    matches: list[LibraryFunction],
    index: LibraryIndex,
    existing_symbol: str,
    size: int,
) -> OracleMatch | None:
    if not matches:
        return None
    distinct_symbols = sorted({f.symbol for f in matches})
    by_symbol = {f.symbol: f for f in matches}

    if len(distinct_symbols) == 1:
        func = by_symbol[distinct_symbols[0]]
        name, proto = friendly_name_and_prototype(func.symbol)
        confidence = "high" if size >= MIN_CONFIDENT_SIZE else "review"
        return OracleMatch(
            address, name, func.symbol, proto,
            index.library_of.get(func.symbol, "?"), func.member,
            "unique", confidence, 1,
        )

    # Ambiguous normal form: try to break the tie with the symbol already present.
    if existing_symbol and existing_symbol in by_symbol:
        func = by_symbol[existing_symbol]
        name, proto = friendly_name_and_prototype(func.symbol)
        return OracleMatch(
            address, name, func.symbol, proto,
            index.library_of.get(func.symbol, "?"), func.member,
            "unique-via-existing", "high", len(distinct_symbols),
        )

    func = by_symbol[distinct_symbols[0]]
    name, proto = friendly_name_and_prototype(func.symbol)
    return OracleMatch(
        address, name, func.symbol, proto,
        index.library_of.get(func.symbol, "?"), func.member,
        "ambiguous", "review", len(distinct_symbols),
    )


def write_oracle(path: Path, matches: list[OracleMatch]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "address", "name", "symbol", "prototype", "library",
        "member", "match_kind", "confidence", "candidate_count",
    ]
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|", lineterminator="\n")
        writer.writeheader()
        for m in sorted(matches, key=lambda x: x.address):
            writer.writerow({
                "address": f"0x{m.address:08x}",
                "name": m.name,
                "symbol": m.symbol,
                "prototype": m.prototype,
                "library": m.library,
                "member": m.member,
                "match_kind": m.match_kind,
                "confidence": m.confidence,
                "candidate_count": m.candidate_count,
            })


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    binary = resolve_binary(repo_root, args.binary)
    symbols_path = resolve_repo_path(repo_root, args.symbols)
    out_path = resolve_repo_path(repo_root, args.out)

    libs = list(DEFAULT_LIBS)
    for extra in args.lib:
        family, _, rel = extra.partition("=")
        if rel:
            libs.append((family, rel))

    if not args.quiet:
        print(f"binary: {binary}")
    index = build_index(repo_root, libs, args.quiet)
    pe = PEImage(binary)

    exe_functions = load_exe_functions(symbols_path)
    matches: list[OracleMatch] = []
    kinds: dict[str, int] = defaultdict(int)
    read_failures = 0
    for address, size, existing_symbol in exe_functions:
        raw = pe.read_va(address, size)
        if raw is None:
            read_failures += 1
            continue
        body, _ = _trim_padding(raw)
        if not body:
            continue
        found = index.match(len(body), body)
        result = classify(address, found, index, existing_symbol, len(body))
        if result is None:
            continue
        matches.append(result)
        kinds[f"{result.match_kind}/{result.confidence}"] += 1

    # Non-discriminative bodies: a real library function appears once (COMDAT
    # folding), so a symbol/normal-form claimed by MULTIPLE executable addresses is
    # a generic body (empty ctor/dtor, `return 0`, trivial thunk) that many distinct
    # functions share. Byte matching cannot tell those apart, so demote every such
    # match to a review kind — it must never be auto-applied on body evidence alone.
    addresses_per_symbol: dict[str, int] = defaultdict(int)
    for m in matches:
        addresses_per_symbol[m.symbol] += 1
    demoted = 0
    for i, m in enumerate(matches):
        if addresses_per_symbol[m.symbol] > 1 and m.confidence == "high":
            matches[i] = OracleMatch(
                m.address, m.name, m.symbol, m.prototype, m.library, m.member,
                "duplicate-body", "review", m.candidate_count,
            )
            demoted += 1
    if demoted:
        kinds.clear()
        for m in matches:
            kinds[f"{m.match_kind}/{m.confidence}"] += 1

    write_oracle(out_path, matches)
    if demoted:
        print(f"  demoted {demoted} matches with bodies shared across multiple addresses")
    print(
        f"library oracle: {len(matches)} matches over {len(exe_functions)} functions "
        f"-> {out_path}"
    )
    for kind in sorted(kinds):
        print(f"  {kind}: {kinds[kind]}")
    if read_failures:
        print(f"  (read failures: {read_failures})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
