#!/usr/bin/env python3
"""Compact committed per-function reccmp baseline storage."""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path
from typing import Any

FIELDS = ("address", "matching", "name")


def load_function_baseline(path: Path) -> dict[str, dict[str, Any]] | None:
    """Load address-keyed effective scores from the committed pipe CSV."""
    if not path.exists():
        return None

    functions: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError(
                f"Unexpected function baseline columns in {path}: {reader.fieldnames}"
            )
        for row in reader:
            address = (row.get("address") or "").strip()
            if not address:
                continue
            functions[address] = {
                "m": float(row.get("matching") or 0.0),
                "n": row.get("name") or "",
            }
    return functions


def write_function_baseline_atomic(
    path: Path, functions: dict[str, dict[str, Any]]
) -> None:
    """Write the minimal baseline fields in stable original-address order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as tmp:
        writer = csv.DictWriter(tmp, fieldnames=FIELDS, delimiter="|", lineterminator="\n")
        writer.writeheader()
        for address, function in sorted(
            functions.items(), key=lambda item: int(item[0], 16)
        ):
            writer.writerow(
                {
                    "address": address,
                    "matching": repr(float(function["m"])),
                    "name": function.get("n", ""),
                }
            )
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)
