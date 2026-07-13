#!/usr/bin/env python3
"""Shared per-file-count ratchet baseline for source-policy gates.

A ratchet baseline is a pipe-delimited CSV of per-file counts for a fixed set of
`keys`. A gate scans the tree, tallies per-file counts, and compares them to the
baseline: a file absent from the baseline (but carrying any tracked count) fails,
and any key whose count rose above its baseline value fails. The baseline lets
pre-existing occurrences stay (ratcheting downward) while blocking new ones.

Used by the construction-anti-pattern, raw-vtable, TGreatPower-hygiene, and
empty-body (NOOP) gates. `check_datacmp_baseline` (opaque fingerprints) and
`check_stub_count` (a single number) are bespoke and deliberately do NOT use this.

Two on-disk shapes exist and must be preserved byte-for-byte:
  - The construction/vtable/tgreatpower baselines carry a trailing `total`
    column and CRLF line endings (csv's default terminator).
  - The empty-body baseline has no `total` column and LF line endings.
Hence `include_total` and `lineterminator` are parameters, not constants.
"""

from __future__ import annotations

import csv
from collections.abc import Callable, Sequence
from pathlib import Path

# file -> {key: count}
PerFileCounts = dict[str, dict[str, int]]


def read_baseline(path: Path, keys: Sequence[str]) -> PerFileCounts:
    """Load a pipe-delimited per-file-count baseline. Missing file -> {}."""
    out: PerFileCounts = {}
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", newline="") as fd:
        for row in csv.DictReader(fd, delimiter="|"):
            file_key = (row.get("file") or "").strip()
            if not file_key:
                continue
            out[file_key] = {k: int((row.get(k) or "0").strip() or 0) for k in keys}
    return out


def write_baseline(
    path: Path,
    data: PerFileCounts,
    keys: Sequence[str],
    *,
    include_total: bool = True,
    lineterminator: str = "\r\n",
) -> None:
    """Write a pipe-delimited per-file-count baseline, sorted by file key.

    `include_total`/`lineterminator` default to the construction/vtable/
    tgreatpower shape (trailing total column, CRLF); the empty-body gate passes
    `include_total=False, lineterminator="\\n"`.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["file", *keys] + (["total"] if include_total else [])
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(
            fd, fieldnames=fieldnames, delimiter="|", lineterminator=lineterminator
        )
        writer.writeheader()
        for file_key in sorted(data):
            row: dict[str, str] = {"file": file_key}
            total = 0
            for key in keys:
                value = data[file_key].get(key, 0)
                total += value
                row[key] = str(value)
            if include_total:
                row["total"] = str(total)
            writer.writerow(row)


def _default_new_file_message(file_key: str, counts: dict[str, int], keys: Sequence[str]) -> str:
    return f"{file_key}: new tracked patterns introduced (not in baseline)"


def compare(
    current: PerFileCounts,
    baseline: PerFileCounts,
    keys: Sequence[str],
    *,
    new_file_message: Callable[[str, dict[str, int]], str] | None = None,
) -> list[str]:
    """The shared "new file fails, per-key increase fails" compare loop.

    Returns violation strings in file-key order. `new_file_message` formats the
    message for a file absent from the baseline (defaults to a generic phrasing);
    per-key increases use a fixed `"<file>: <key> increased A -> B"` message.
    Gate-specific extra rules (e.g. the NOOP-contradicted always-fail) stay in
    the caller.
    """
    violations: list[str] = []
    for file_key, counts in sorted(current.items()):
        base_counts = baseline.get(file_key)
        if base_counts is None:
            if new_file_message is None:
                violations.append(_default_new_file_message(file_key, counts, keys))
            else:
                violations.append(new_file_message(file_key, counts))
            continue
        for key in keys:
            cur = counts.get(key, 0)
            base = base_counts.get(key, 0)
            if cur > base:
                violations.append(f"{file_key}: {key} increased {base} -> {cur}")
    return violations
