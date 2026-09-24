#!/usr/bin/env python3
"""Reject source-level compiler tuning used only to chase binary similarity.

Recovered source should describe the retail program. Per-function/per-call compiler controls
encode toolchain accidents into the source model and are therefore a hard error. ABI/layout
pragmas such as #pragma pack are intentionally outside this gate.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path, strip_generated_blocks
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

DEFAULT_EXTENSIONS = {".h", ".hpp", ".c", ".cc", ".cpp"}

CODEGEN_PRAGMA = re.compile(
    r"^\s*#\s*pragma\s+"
    r"(?:inline_depth|inline_recursion|auto_inline|optimize|intrinsic|function)\b",
    re.MULTILINE,
)
CODEGEN_WRAPPER = re.compile(
    r"\bIMPERIALISM_(?:BEGIN|END)_DISABLE_AUTOMATIC_INLINING\b"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--roots",
        nargs="+",
        default=["src", "include"],
        help="Root paths to scan.",
    )
    return parser.parse_args()


def collect_files(repo_root: Path, roots: list[str]) -> list[Path]:
    files: list[Path] = []
    for root_value in roots:
        root = resolve_repo_path(repo_root, root_value)
        if not root.exists():
            continue
        if root.is_file():
            if root.suffix.lower() in DEFAULT_EXTENSIONS:
                files.append(root)
            continue
        for path in root.rglob("*"):
            if is_excluded_scan_path(path, roots=[root]):
                continue
            if path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS:
                files.append(path)
    return sorted(set(files))


def findings(file_path: Path) -> list[tuple[int, str]]:
    text = strip_generated_blocks(file_path.read_text(encoding="utf-8", errors="ignore"))
    result: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if CODEGEN_PRAGMA.search(line) or CODEGEN_WRAPPER.search(line):
            result.append((line_number, line.strip()))
    return result


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    offenders: dict[str, list[tuple[int, str]]] = {}
    for file_path in collect_files(repo_root, args.roots):
        hits = findings(file_path)
        if hits:
            offenders[normalize_repo_relative_path(file_path, repo_root)] = hits

    if offenders:
        print("Codegen tuning gate failed (hard ban -- zero occurrences allowed):")
        for rel in sorted(offenders):
            for line_number, line in offenders[rel]:
                print(f"  - {rel}:{line_number}: {line}")
        print("Express the retail source model naturally; do not tune compiler output for reccmp.")
        return 1

    print("Codegen tuning gate passed (hard ban -- zero offenders).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
