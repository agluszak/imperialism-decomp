"""Scoring helpers for reccmp JSON report rows."""

from typing import Any


def effective_matching(row: dict[str, Any]) -> float:
    """Similarity of a report row, honoring the effective-match flag.

    An effective match differs from the original only in ways that don't
    affect behavior (register choice, commutative operand order, ...), so
    it counts as 1.0. Scoring the raw `matching` instead makes stats and
    target rankings flap with compiler entropy (e.g. the TGreatPower x87
    leaves, which swap fld/fadd operand chains on every recompile).
    """
    if row.get("effective"):
        return 1.0
    return float(row.get("matching", 0.0))
