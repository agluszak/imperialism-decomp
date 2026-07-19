#!/usr/bin/env python3
"""Build the source index: every address claimed by a marker in manual source.

Manual C++ source is the authority for which original addresses are implemented,
owned, or otherwise claimed (`// FUNCTION:` / `// SYNTHETIC:` / `// TEMPLATE:` /
`// LIBRARY:` / `// STUB:` markers in `src/` + `include/`). This module scans those
markers directly — no ownership ledger, no sync step — and writes the result to
`<build_dir>/generated/source_index.json` for downstream generators (stub
generation, gates, reccmp overlays).

The index is a disposable build artifact: regenerate it any time with

  uv run python -m tools.source_index [--gen-dir build-msvc500/generated]

Duplicate claims (two function-kind markers for one address) are a hard error —
one address, one owner (Hard Rule 4).
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from tools.common.file_scan import iter_files, is_generated_source_path
from tools.common.markers import function_marker_regex
from tools.common.repo import repo_root_from_file, resolve_repo_path

DEFAULT_GEN_DIR = "build-msvc500/generated"
SOURCE_INDEX_NAME = "source_index.json"

# The marker keyword actually used on the matched line (FUNCTION/STUB/...).
# function_marker_regex captures only the address, so re-read the kind per line.
_KINDS = ("FUNCTION", "STUB", "TEMPLATE", "SYNTHETIC", "LIBRARY")


@dataclass(frozen=True)
class MarkerClaim:
    address: int
    kind: str
    file: str  # repo-relative posix path
    line: int  # 1-based


def scan_marker_claims(
    repo_root: Path, target: str, roots: tuple[str, ...] = ("src", "include")
) -> list[MarkerClaim]:
    """Every function-kind marker claim in manual source, sorted by address."""
    rx = function_marker_regex(target)
    claims: list[MarkerClaim] = []
    for path in iter_files([str(repo_root / r) for r in roots]):
        if is_generated_source_path(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.resolve().relative_to(repo_root.resolve()).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = rx.search(line)
            if not m:
                continue
            kind = next((k for k in _KINDS if k in line.upper()), "FUNCTION")
            claims.append(
                MarkerClaim(address=int(m.group(1), 16), kind=kind, file=rel, line=lineno)
            )
    claims.sort(key=lambda c: (c.address, c.file, c.line))
    return claims


def find_duplicate_claims(claims: list[MarkerClaim]) -> dict[int, list[MarkerClaim]]:
    by_addr: dict[int, list[MarkerClaim]] = {}
    for c in claims:
        by_addr.setdefault(c.address, []).append(c)
    return {a: cs for a, cs in by_addr.items() if len(cs) > 1}


def claimed_addresses(repo_root: Path, target: str) -> set[int]:
    """The set of addresses claimed by any function-kind marker in manual source."""
    return {c.address for c in scan_marker_claims(repo_root, target)}


def ownership_kind(kind: str) -> str:
    """Map a marker kind to the coarse ownership bucket the old ledger used."""
    return "library" if kind == "LIBRARY" else "manual"


def ownership_view(repo_root: Path, target: str = "IMPERIALISM") -> dict[int, MarkerClaim]:
    """addr -> claim, the marker-derived replacement for the retired ownership CSV.

    The claim's `file` is the owning source file (what the ledger called
    `target_cpp`) and `ownership_kind(claim.kind)` is the manual/library bucket.
    """
    out: dict[int, MarkerClaim] = {}
    for c in scan_marker_claims(repo_root, target):
        out.setdefault(c.address, c)
    return out


def build_index(repo_root: Path, target: str) -> dict:
    claims = scan_marker_claims(repo_root, target)
    return {
        "target": target,
        "functions": [
            {
                "address": "0x{:08x}".format(c.address),
                "kind": c.kind,
                "file": c.file,
                "line": c.line,
            }
            for c in claims
        ],
    }


def write_index(repo_root: Path, target: str, gen_dir: Path) -> tuple[Path, int, dict]:
    claims = scan_marker_claims(repo_root, target)
    dupes = find_duplicate_claims(claims)
    gen_dir.mkdir(parents=True, exist_ok=True)
    out = gen_dir / SOURCE_INDEX_NAME
    out.write_text(
        json.dumps(build_index(repo_root, target), indent=1) + "\n", encoding="utf-8"
    )
    return out, len(claims), dupes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--gen-dir", default=DEFAULT_GEN_DIR)
    args = parser.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=1)
    gen_dir = resolve_repo_path(repo_root, args.gen_dir)
    out, count, dupes = write_index(repo_root, args.target, gen_dir)
    print("Wrote {} ({} marker claim(s))".format(out, count))
    if dupes:
        print("source-index FAILED: duplicate function-kind markers (one address, one owner):")
        for addr in sorted(dupes):
            for c in dupes[addr]:
                print("  0x{:08x} {} {}:{}".format(addr, c.kind, c.file, c.line))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
