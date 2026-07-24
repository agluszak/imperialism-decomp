"""Hash-keyed original-to-recomp function addresses for debugger probes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.common.reccmp_report import run_report


FORMAT_VERSION = 1


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _address(value: object) -> int | None:
    if not isinstance(value, str) or value == "various":
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def matching_addresses(
    target: str, build_dir: Path, original_addresses: tuple[int, ...]
) -> dict[int, int]:
    """Resolve all requested probes in one report and cache by recomp PE hash."""
    executable = build_dir / "Imperialism.exe"
    if not executable.is_file():
        raise RuntimeError(f"missing matching executable {executable}")
    binary_hash = _sha256(executable)
    cache_path = build_dir / "debug-map.json"
    cached: dict = {}
    try:
        candidate = json.loads(cache_path.read_text(encoding="utf-8"))
        if (
            candidate.get("format_version") == FORMAT_VERSION
            and candidate.get("binary_sha256") == binary_hash
        ):
            cached = candidate
    except (OSError, ValueError):
        pass
    functions = cached.get("functions")
    if not isinstance(functions, dict):
        functions = {}
    missing = [address for address in original_addresses if f"0x{address:08x}" not in functions]
    if missing:
        rows = run_report(target, build_dir, diet=True, orig_addresses=missing)
        by_original = {
            original: row
            for row in rows
            if (original := _address(row.get("address"))) is not None
        }
        unresolved = [address for address in missing if address not in by_original]
        if unresolved:
            rows = run_report(target, build_dir, diet=True)
            by_original.update(
                {
                    original: row
                    for row in rows
                    if (original := _address(row.get("address"))) is not None
                }
            )
        for original in missing:
            row = by_original.get(original)
            recomp = _address(row.get("recomp")) if row is not None else None
            if recomp is None:
                raise RuntimeError(f"no recomp address for debugger probe 0x{original:08x}")
            functions[f"0x{original:08x}"] = {
                "name": row.get("name"),
                "original": f"0x{original:08x}",
                "recomp": f"0x{recomp:08x}",
            }
        cache_path.write_text(
            json.dumps(
                {
                    "format_version": FORMAT_VERSION,
                    "binary_sha256": binary_hash,
                    "functions": functions,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return {
        address: int(functions[f"0x{address:08x}"]["recomp"], 16)
        for address in original_addresses
    }
