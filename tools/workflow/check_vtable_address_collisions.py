#!/usr/bin/env python3
"""Gate against address collisions that hide `// VTABLE:` entities from reccmp.

A class vtable address must be owned by exactly *one* reccmp entity: the `// VTABLE:`
annotation in the source (paired with real C++ inheritance). reccmp keys entities by
address, so if a *second* entity claims the same address, reccmp drops one as a
duplicate -- and the survivor is usually the wrong type (DATA / global), so the vtable
silently never pairs and `reccmp-vtable <Class>` shows nothing.

Two ways that second claim sneaks in, both gated here:

1. ANY row in `config/original_entities.csv` whose address equals a `// VTABLE:` address --
   including rows typed `vtable` themselves. reccmp ingests symbols.csv as ORIG-image
   entities *after* the source markers, so any row here overwrites the `name` attribute
   the `// VTABLE:` marker + class declaration already derived correctly. In practice
   these were stale `X::'vftable'` (or worse, plain `'vftable'`-suffixed) rows left over
   from before the class was modeled with real inheritance; even when the embedded class
   name happened to still be correct, the row's `name` value was the whole
   `"Class::'vftable'"` string rather than the bare class name reccmp's vtable matcher
   expects, so it broke the match regardless. (This silently cost 64 vtables -- see
   commit history.) The fix is always to delete the row; the annotation is the only
   source of truth for a vtable's name.

2. A `// GLOBAL:` annotation in the source at a `// VTABLE:` address -- typically left on
   a legacy `PTR_Get*RuntimeClass*` vptr-write stand-in. Remove the `// GLOBAL:` marker;
   the `// VTABLE:` annotation + inheritance already own that address.

Check-only; it never edits files.
"""

from __future__ import annotations

import argparse
import re

from tools.common.file_scan import iter_files
from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file


def addr_key(raw: str) -> int | None:
    """Canonicalize an address to an int so `644778` == `0x00644778` (no leading-zero or
    0x-prefix mismatches). Returns None if the value is not a hex address."""
    text = raw.strip().lower().removeprefix("0x")
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None

VTABLE_MARKER_RE = re.compile(
    r"^\s*//\s*VTABLE\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)
GLOBAL_MARKER_RE = re.compile(
    r"^\s*//\s*GLOBAL\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)

def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["src", "include"],
        help="Files or directories to scan for annotations.",
    )
    parser.add_argument(
        "--symbols-csv",
        default=str(repo_root / "config" / "original_entities.csv"),
        help="Path to symbols.csv (pipe-delimited).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    # Collect every // VTABLE: address (as an int) and where it is declared.
    vtable_addrs: dict[int, str] = {}
    global_markers: list[tuple[int, str]] = []  # (addr_int, "rel:line")

    for path in iter_files(args.paths):
        rel = normalize_repo_relative_path(path, repo_root)
        for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines()):
            vt = VTABLE_MARKER_RE.match(line)
            if vt is not None:
                addr = addr_key(vt.group("offset"))
                if addr is not None:
                    vtable_addrs.setdefault(addr, f"{rel}:{idx + 1}")
                continue
            gl = GLOBAL_MARKER_RE.match(line)
            if gl is not None:
                addr = addr_key(gl.group("offset"))
                if addr is not None:
                    global_markers.append((addr, f"{rel}:{idx + 1}"))

    violations: list[str] = []

    # (1) any symbols.csv row at a VTABLE address (including type 'vtable' itself --
    # it always overwrites the marker-derived name and breaks the match; see module docstring).
    from pathlib import Path

    symbols_path = Path(args.symbols_csv)
    if symbols_path.exists():
        for row in read_pipe_rows(symbols_path):
            addr = addr_key(row.get("address") or "")
            row_type = (row.get("type") or "").strip().lower()
            if addr is None or addr not in vtable_addrs:
                continue
            name = (row.get("name") or "").strip()
            violations.append(
                f"symbols.csv: 0x{addr:x} typed '{row_type}' ({name!r}) collides with the "
                f"// VTABLE: at {vtable_addrs[addr]} -- delete the row"
            )

    # (2) // GLOBAL: annotation at a VTABLE address.
    for addr, loc in global_markers:
        if addr in vtable_addrs:
            violations.append(
                f"{loc}: // GLOBAL 0x{addr:x} collides with the // VTABLE: at "
                f"{vtable_addrs[addr]} -- remove the // GLOBAL marker (the // VTABLE "
                f"annotation owns this address)"
            )

    print(f"// VTABLE addresses scanned: {len(vtable_addrs)}")

    if not violations:
        print("VTABLE address-collision gate passed.")
        return 0

    print("VTABLE address-collision gate failed:")
    for item in sorted(violations):
        print(f"    - {item}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
