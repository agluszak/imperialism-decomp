#!/usr/bin/env python3
"""Gate reccmp marker hygiene (AGENTS.md Hard Rules 3 and 4).

Rule 3: a `// FUNCTION: <MODULE> 0x...` marker must be immediately followed by the
        function declaration -- no blank line and no comment line in between.
Rule 4: each address may own at most one `// FUNCTION` marker across the whole tree
        (manual source and generated stubs combined).

This is a check-only gate; it never edits files. Marker *reformatting* is handled
separately by `tools.workflow.normalize_reccmp_markers`.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

FUNCTION_MARKER_RE = re.compile(
    r"^\s*//\s*FUNCTION\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths", nargs="+", default=["src", "include"], help="Files or directories to scan.")
    return parser.parse_args()


def normalize_offset(raw: str) -> str:
    return f"0x{raw.lower().removeprefix('0x')}"


def is_declaration_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("//"):
        return False
    return True


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    rule3_violations: list[str] = []
    address_owners: dict[str, list[str]] = defaultdict(list)

    for path in iter_files(args.paths):
        rel = normalize_repo_relative_path(path, repo_root)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, line in enumerate(lines):
            match = FUNCTION_MARKER_RE.match(line)
            if match is None:
                continue
            offset = normalize_offset(match.group("offset"))
            address_owners[offset].append(f"{rel}:{idx + 1}")

            next_line = lines[idx + 1] if idx + 1 < len(lines) else ""
            if not is_declaration_line(next_line):
                reason = "blank line" if not next_line.strip() else "comment line"
                rule3_violations.append(
                    f"{rel}:{idx + 1}: // FUNCTION {offset} not immediately followed by a declaration ({reason})"
                )

    rule4_violations = {addr: locs for addr, locs in address_owners.items() if len(locs) > 1}

    total_markers = sum(len(locs) for locs in address_owners.values())
    print(f"Scanned // FUNCTION markers: {total_markers} ({len(address_owners)} distinct addresses)")

    if not rule3_violations and not rule4_violations:
        print("Marker hygiene gate passed.")
        return 0

    print("Marker hygiene gate failed:")
    if rule3_violations:
        print("  Rule 3 (marker must precede declaration):")
        for item in sorted(rule3_violations):
            print(f"    - {item}")
    if rule4_violations:
        print("  Rule 4 (one owned implementation per address):")
        for addr in sorted(rule4_violations):
            print(f"    - {addr}: {', '.join(rule4_violations[addr])}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
