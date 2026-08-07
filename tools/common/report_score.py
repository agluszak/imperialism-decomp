"""Scoring helpers for reccmp JSON report rows."""

from typing import Any


def effective_matching(row: dict[str, Any]) -> float:
    """Similarity of a current-schema report row, honoring semantic status.

    An effective match differs from the original only in ways that don't
    affect behavior (register choice, commutative operand order, ...), so
    it counts as 1.0. Scoring the raw `matching` instead makes stats and
    target rankings flap with compiler entropy (e.g. the TGreatPower x87
    leaves, which swap fld/fadd operand chains on every recompile).
    """
    comparison = row.get("comparison")
    if not isinstance(comparison, dict):
        raise ValueError("reccmp report row lacks structured comparison data")
    if comparison.get("status") in {"exact", "effective"}:
        return 1.0
    return float(row.get("matching", 0.0))


def semantic_matching(row: dict[str, Any]) -> float:
    """Diagnostic semantic similarity, falling back when it is unavailable.

    Exact and effective rows are semantically complete. A mismatch may carry a
    partial semantic score; inconclusive and structurally unsupported rows often
    do not. Those rows retain the existing effective/raw score rather than being
    omitted or counted as zero.
    """
    comparison = row.get("comparison")
    if not isinstance(comparison, dict):
        raise ValueError("reccmp report row lacks structured comparison data")
    value = comparison.get("semantic_similarity")
    if value is None:
        return effective_matching(row)
    score = float(value)
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"semantic similarity outside [0, 1]: {score}")
    return score
