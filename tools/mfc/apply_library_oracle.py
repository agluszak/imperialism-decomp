#!/usr/bin/env python3
"""Apply the relocation-masked library oracle to the derived artifacts.

Consumes `config/msvc500_library_oracle.csv` (built by build_library_oracle.py)
and projects its confident, unique matches into symbols.csv + a generated
`// LIBRARY:` marker file, with strict precedence and conservative safety guards.

Precedence (highest first), per the identity design:
  reviewed override > unique object-file match > FID > manually curated source
  identity > provisional Ghidra identity.

So this applier:
  - SKIPS addresses owned by a reviewed override (apply_library_overrides owns them).
  - Only acts on match_kind in {unique, unique-via-existing} at confidence=high.
  - **library-owned rows**: upgrades the exact linker `symbol` (e.g. a friendly
    `AddBitmap` -> `?AddBitmap@CToolBarCtrl@@...`) and the prototype. No ownership
    or marker change, so linking cannot be affected.
  - **unowned rows** (FID missed them; currently autogen-stubbed): if the function
    is large enough to trust and its current invented name is NOT referenced by any
    manual source, it gets the real name/symbol/prototype and a `// LIBRARY:` marker
    -> ownership=library (its autogen stub disappears; safe because unreferenced).
  - **manually curated game code**: never rewritten. A high-confidence library
    match owned by game code is a mislabel (e.g. libcmt float-conversion internals
    ported as `bignum96_math.cpp`); it is routed to the review queue and flagged by
    library-identity-gate rather than silently reverting someone's port.

Ambiguous / low-confidence oracle rows are left in the oracle CSV as a review
queue and never applied.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows, read_pipe_table
from tools.common.repo import (
    normalize_repo_relative_path,
    repo_root_from_file,
    resolve_repo_path,
)
from tools.ghidra.merge_curated_symbols import write_symbols_csv
from tools.mfc.apply_library_overrides import load_overrides
from tools.mfc.apply_msvc500_library_region import (
    collect_manual_source_references,
    collect_source_markers,
)

DEFAULT_ORACLE = "config/msvc500_library_oracle.csv"
DEFAULT_SYMBOLS = "config/symbols.csv"
DEFAULT_OWNERSHIP = "config/function_ownership.csv"
DEFAULT_OVERRIDES = "config/msvc500_library_overrides.csv"
DEFAULT_MARKERS = "src/game/library_msvc500_oracle.cpp"
DEFAULT_REVIEW = "config/msvc500_library_oracle_review.csv"
PROVENANCE = "msvc500_library_oracle"

# Minimum function size to auto-convert an *unowned* row to library ownership.
# A full masked match at this size is effectively collision-free; smaller unique
# matches are recorded for review instead of changing ownership.
MIN_CONVERT_SIZE = 12

# Auto-conversion of an *unowned* row to library ownership is restricted to the
# dense MFC/CRT library region (the range apply_msvc500_library_region also uses).
# A unique body match for an unowned function OUTSIDE this region is far more
# likely a coincidental trivial-body collision with real game code, so it is routed
# to review instead. In-region matches are the genuine FID misses.
LIBRARY_RANGE = (0x005E539C, 0x00626C7D)

APPLY_KINDS = {"unique", "unique-via-existing"}
GHIDRA_ADDR_SUFFIX = re.compile(r"_[0-9A-Fa-f]{6,8}$")
PROVISIONAL_PROTO = re.compile(r"^\s*(undefined|$)")


@dataclass(frozen=True)
class OracleRow:
    address: int
    name: str
    symbol: str
    prototype: str
    library: str
    member: str
    match_kind: str
    confidence: str
    candidate_count: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--ownership", default=DEFAULT_OWNERSHIP)
    parser.add_argument("--overrides", default=DEFAULT_OVERRIDES)
    parser.add_argument("--markers", default=DEFAULT_MARKERS)
    parser.add_argument("--review-out", default=DEFAULT_REVIEW)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--min-convert-size", type=int, default=MIN_CONVERT_SIZE)
    return parser.parse_args()


def load_oracle(path: Path) -> list[OracleRow]:
    rows: list[OracleRow] = []
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            address = int(addr_text, 16)
        except ValueError:
            continue
        try:
            candidate_count = int(row.get("candidate_count") or "0")
        except ValueError:
            candidate_count = 0
        rows.append(
            OracleRow(
                address=address,
                name=(row.get("name") or "").strip(),
                symbol=(row.get("symbol") or "").strip(),
                prototype=(row.get("prototype") or "").strip(),
                library=(row.get("library") or "").strip(),
                member=(row.get("member") or "").strip(),
                match_kind=(row.get("match_kind") or "").strip(),
                confidence=(row.get("confidence") or "").strip(),
                candidate_count=candidate_count,
            )
        )
    return rows


def load_ownership_map(path: Path) -> dict[int, tuple[str, str]]:
    out: dict[int, tuple[str, str]] = {}
    for row in read_pipe_rows(path):
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            out[int(addr_text, 16)] = (
                (row.get("target_cpp") or "").strip(),
                (row.get("ownership") or "").strip().lower(),
            )
        except ValueError:
            continue
    return out


def is_provisional_name(name: str) -> bool:
    return not name or bool(GHIDRA_ADDR_SUFFIX.search(name))


def render_marker_file(rows: list[OracleRow], *, target: str) -> str:
    lines = [
        "// AUTO-GENERATED by tools/mfc/apply_library_oracle.py -- do not hand-edit.",
        "// Relocation-masked object-matcher identities (config/msvc500_library_oracle.csv)",
        "// for CRT/MFC functions FID missed. Ownership derives from these // LIBRARY:",
        "// markers via sync-ownership. Rebuild with `just build-library-oracle`, then",
        "// re-project with `just apply-library-oracle`; edit neither this file directly.",
        "",
        "#if 0",
    ]
    for row in sorted(rows, key=lambda r: r.address):
        lines.append(f"// LIBRARY: {target} 0x{row.address:08x}")
        lines.append(f"// {row.symbol}")
        lines.append("")
    lines.append("#endif")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    oracle_path = resolve_repo_path(repo_root, args.oracle)
    symbols_path = resolve_repo_path(repo_root, args.symbols)
    ownership_path = resolve_repo_path(repo_root, args.ownership)
    overrides_path = resolve_repo_path(repo_root, args.overrides)
    marker_path = resolve_repo_path(repo_root, args.markers)
    marker_rel = normalize_repo_relative_path(marker_path, repo_root)
    review_path = resolve_repo_path(repo_root, args.review_out)

    if not oracle_path.is_file():
        raise SystemExit(f"oracle not found: {oracle_path}. Run `just build-library-oracle` first.")

    oracle = load_oracle(oracle_path)
    ownership = load_ownership_map(ownership_path)
    override_addrs = {o.address for o in load_overrides(overrides_path)} if overrides_path.is_file() else set()
    existing_markers = collect_source_markers(repo_root, args.target)

    fieldnames, rows = read_pipe_table(symbols_path)
    for column in ("symbol", "provenance"):
        if column not in fieldnames:
            fieldnames.append(column)
    by_addr = {int(r["address"], 16): r for r in rows if (r.get("address") or "").strip()}

    # Names we might reference-check, to avoid breaking the link when a stub is removed.
    candidate_names = {
        (by_addr.get(r.address, {}).get("name") or "")
        for r in oracle
        if r.match_kind in APPLY_KINDS and r.confidence == "high"
        and r.address not in override_addrs
        and ownership.get(r.address) is None
        and r.address not in existing_markers
    }
    referenced = collect_manual_source_references(
        repo_root, {n for n in candidate_names if n}, marker_rel=marker_rel
    )

    upgraded = 0
    converted: list[OracleRow] = []
    review: list[dict[str, str]] = []

    for r in oracle:
        if r.match_kind not in APPLY_KINDS or r.confidence != "high":
            continue
        if r.address in override_addrs:
            continue
        owner = ownership.get(r.address)
        row = by_addr.get(r.address)
        cur_name = (row.get("name") if row else "") or ""

        if owner is not None and owner[1] == "library":
            # Case A: upgrade the durable linker symbol + prototype. No link change.
            if row is None:
                continue
            changed = False
            if r.symbol and row.get("symbol", "") != r.symbol:
                row["symbol"] = r.symbol
                changed = True
            if r.prototype and PROVISIONAL_PROTO.match(row.get("prototype", "") or ""):
                row["prototype"] = r.prototype
                changed = True
            if r.name and is_provisional_name(cur_name):
                row["name"] = r.name
                changed = True
            if changed:
                row["provenance"] = PROVENANCE
                upgraded += 1
            continue

        if owner is not None:
            # Case C: manual game-code ownership. Never rewrite; flag for review.
            review.append(_review_row(r, cur_name, f"{owner[1]}:{owner[0]}", "match_owned_by_game_code"))
            continue

        # Case B: unowned (autogen-stubbed). Convert to library if safe.
        if not (LIBRARY_RANGE[0] <= r.address <= LIBRARY_RANGE[1]):
            review.append(_review_row(r, cur_name, "unowned", "outside_library_range"))
            continue
        size = _row_size(row)
        if size is not None and size < args.min_convert_size:
            review.append(_review_row(r, cur_name, "unowned", "below_min_convert_size"))
            continue
        if cur_name and cur_name in referenced:
            review.append(_review_row(r, cur_name, "unowned", "invented_name_referenced_in_source"))
            continue
        marker = existing_markers.get(r.address)
        if marker is not None and getattr(marker, "path", "") != marker_rel:
            # A // LIBRARY:/FUNCTION: marker in another file already claims this
            # address; converting here would duplicate ownership.
            review.append(_review_row(r, cur_name, "unowned", "marker_conflict"))
            continue
        # Apply full identity + schedule a // LIBRARY: marker. (A marker this file
        # already owns from a prior run just means idempotent re-conversion — the
        # ownership row lags the marker by one sync-ownership step.)
        if row is None:
            row = {"address": format(r.address, "x"), "size": "", "type": "function"}
            rows.append(row)
            by_addr[r.address] = row
        row["name"] = r.name
        row["symbol"] = r.symbol
        row["type"] = "function"
        if r.prototype:
            row["prototype"] = r.prototype
        row["provenance"] = PROVENANCE
        converted.append(r)

    # Write marker file (converted addresses + any this file already owned).
    owned_here = sorted(
        {r.address for r in converted}
        | {a for a, m in existing_markers.items() if getattr(m, "path", "") == marker_rel},
    )
    marker_rows = {r.address: r for r in converted}
    # Rows this file already owns but that aren't freshly converted still need a body line.
    for addr in owned_here:
        if addr not in marker_rows:
            existing = next((r for r in oracle if r.address == addr), None)
            if existing is not None:
                marker_rows[addr] = existing
    marker_text = render_marker_file(list(marker_rows.values()), target=args.target)
    marker_changed = (
        not marker_path.is_file() or marker_path.read_text(encoding="utf-8") != marker_text
    )
    if marker_changed:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(marker_text, encoding="utf-8")

    if upgraded or converted:
        rows.sort(key=lambda row: int((row.get("address") or "0"), 16))
        write_symbols_csv(symbols_path, fieldnames, rows)

    _write_review(review_path, review)

    print(
        f"library oracle applied: symbol_upgrades={upgraded} converted_to_library={len(converted)} "
        f"review_queue={len(review)} marker_file={'rewritten' if marker_changed else 'unchanged'}"
    )
    reasons: dict[str, int] = {}
    for item in review:
        reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
    for reason in sorted(reasons):
        print(f"  review/{reason}: {reasons[reason]}")
    return 0


def _row_size(row: dict[str, str] | None) -> int | None:
    if row is None:
        return None
    text = (row.get("size") or "").strip()
    try:
        return int(text)
    except ValueError:
        return None


def _review_row(r: OracleRow, cur_name: str, ownership: str, reason: str) -> dict[str, str]:
    return {
        "address": f"0x{r.address:08x}",
        "current_name": cur_name,
        "current_ownership": ownership,
        "oracle_symbol": r.symbol,
        "oracle_name": r.name,
        "member": r.member,
        "match_kind": r.match_kind,
        "candidate_count": str(r.candidate_count),
        "reason": reason,
    }


def _write_review(path: Path, review: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "address", "current_name", "current_ownership", "oracle_symbol",
        "oracle_name", "member", "match_kind", "candidate_count", "reason",
    ]
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|", lineterminator="\n")
        writer.writeheader()
        for item in sorted(review, key=lambda x: int(x["address"], 16)):
            writer.writerow(item)


if __name__ == "__main__":
    raise SystemExit(main())
