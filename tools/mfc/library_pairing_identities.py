#!/usr/bin/env python3
"""Build ephemeral reccmp identities from the exact MSVC500 library oracle.

The relocation-masked object oracle deliberately remains separate from curated names.
This module selects only identities that are unique on *both* sides: one original
address for a decorated archive symbol and one recomp PDB address for that symbol.
It writes a reccmp-compatible data source; ambiguous/colliding symbols are reported
rather than paired by address or archive order.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from reccmp.cvdump import Cvdump

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path

DEFAULT_ORACLE = "build-msvc500/evidence/library/msvc500_library_oracle.csv"
DEFAULT_PDB = "build-msvc500/Imperialism.pdb"
DEFAULT_OUT = "build-msvc500/evidence/library/reccmp_library_identities.csv"
DEFAULT_REPORT = "build-msvc500/evidence/library/reccmp_library_identity_report.csv"


@dataclass(frozen=True)
class ExactIdentity:
    address: int
    symbol: str
    library: str
    member: str


@dataclass(frozen=True)
class IdentityDecision:
    identity: ExactIdentity
    status: str
    recomp_candidate_count: int
    original_candidate_count: int


def select_exact_identities(
    rows: Iterable[Mapping[str, str]], recomp_symbol_counts: Mapping[str, int]
) -> list[IdentityDecision]:
    """Classify exact-oracle rows without making an arbitrary duplicate choice.

    Only ``unique/high`` object matches are candidates.  The oracle's ``ambiguous``,
    ``duplicate-body`` and ``unique-via-existing`` rows are evidence/report rows,
    not independent identities, so they are retained as non-selected decisions.
    A decorated identity is selected only when it occurs once in candidate original
    rows and once in the recomp PDB.
    """
    parsed: list[tuple[ExactIdentity, str, str]] = []
    for row in rows:
        address_text = (row.get("address") or "").strip()
        symbol = (row.get("symbol") or "").strip()
        if not address_text or not symbol:
            continue
        try:
            address = int(address_text, 16)
        except ValueError:
            continue
        parsed.append(
            (
                ExactIdentity(
                    address,
                    symbol,
                    (row.get("library") or "?").strip(),
                    (row.get("member") or "?").strip(),
                ),
                (row.get("match_kind") or "").strip(),
                (row.get("confidence") or "").strip(),
            )
        )

    eligible_counts = Counter(
        identity.symbol
        for identity, kind, confidence in parsed
        if kind == "unique" and confidence == "high"
    )
    decisions: list[IdentityDecision] = []
    for identity, kind, confidence in parsed:
        orig_count = eligible_counts.get(identity.symbol, 0)
        recomp_count = int(recomp_symbol_counts.get(identity.symbol, 0))
        if kind != "unique" or confidence != "high":
            status = f"oracle-{kind or 'unknown'}-{confidence or 'unknown'}"
        elif orig_count != 1:
            status = "ambiguous-original-symbol"
        elif recomp_count == 0:
            status = "missing-recomp-symbol"
        elif recomp_count != 1:
            status = "ambiguous-recomp-symbol"
        else:
            status = "selected"
        decisions.append(
            IdentityDecision(identity, status, recomp_count, orig_count)
        )
    return decisions


def recomp_public_symbol_counts(pdb_path: Path) -> Counter[str]:
    parser = Cvdump(str(pdb_path)).publics().run()
    return Counter(pub.name for pub in parser.publics)


def write_identity_source(path: Path, decisions: Iterable[IdentityDecision]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(
            fd, fieldnames=("address", "symbol", "type"), delimiter="|", lineterminator="\n"
        )
        writer.writeheader()
        for decision in sorted(decisions, key=lambda d: d.identity.address):
            if decision.status == "selected":
                writer.writerow(
                    {
                        "address": f"0x{decision.identity.address:08x}",
                        "symbol": decision.identity.symbol,
                        "type": "function",
                    }
                )


def write_report(path: Path, decisions: Iterable[IdentityDecision]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "address", "symbol", "library", "member", "status",
        "original_candidate_count", "recomp_candidate_count",
    )
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=fields, delimiter="|", lineterminator="\n")
        writer.writeheader()
        for d in sorted(decisions, key=lambda value: value.identity.address):
            writer.writerow(
                {
                    "address": f"0x{d.identity.address:08x}",
                    "symbol": d.identity.symbol,
                    "library": d.identity.library,
                    "member": d.identity.member,
                    "status": d.status,
                    "original_candidate_count": d.original_candidate_count,
                    "recomp_candidate_count": d.recomp_candidate_count,
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", default=DEFAULT_ORACLE)
    parser.add_argument("--pdb", default=DEFAULT_PDB)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root_from_file(__file__)
    oracle = resolve_repo_path(root, args.oracle)
    pdb = resolve_repo_path(root, args.pdb)
    rows = read_pipe_rows(oracle)
    decisions = select_exact_identities(rows, recomp_public_symbol_counts(pdb))
    write_identity_source(resolve_repo_path(root, args.out), decisions)
    write_report(resolve_repo_path(root, args.report), decisions)

    statuses = Counter(decision.status for decision in decisions)
    print(f"library pairing identities: {statuses.get('selected', 0)} selected -> {args.out}")
    for status, count in sorted(statuses.items()):
        print(f"  {status}: {count}")
    selected_by_member: dict[tuple[str, str], int] = defaultdict(int)
    for decision in decisions:
        if decision.status == "selected":
            selected_by_member[(decision.identity.library, decision.identity.member)] += 1
    print(f"  selected archive members: {len(selected_by_member)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
