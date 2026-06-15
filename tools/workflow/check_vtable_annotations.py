#!/usr/bin/env python3
"""Gate `// VTABLE:` annotation placement.

A `// VTABLE: <MODULE> 0x...` annotation tells reccmp which class owns a vtable at
the given address. reccmp pairs the annotation to the *next class/struct definition*
that follows it, skipping intervening comment and blank lines. If the annotation is
orphaned -- i.e. some other code appears before any class definition -- reccmp either
attaches it to the wrong class or drops it silently.

This gate enforces that every `// VTABLE:` annotation is *immediately* followed by a
`class`/`struct` definition -- no blank line and no comment line in between -- so the
annotation always sits right next to the class it describes. Put any descriptive
comment *above* the `// VTABLE:` line, not between it and the class.

Check-only; it never edits files.
"""

from __future__ import annotations

import argparse
import re

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

VTABLE_MARKER_RE = re.compile(
    r"^\s*//\s*VTABLE\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)

# Mirrors reccmp's parser/util.py class_decl_regex: the next class/struct line after a
# `// VTABLE:` annotation is captured as the owning class -- so a bare forward
# declaration (`struct CRuntimeClass;`) would steal the annotation and name the vtable
# after the forward-declared type. Require a *real definition*: the line must open a
# body (`{`) or declare a base list (`:`) on the same line, and must not be a bare
# forward declaration ending in `;`.
CLASS_DECL_RE = re.compile(r"^\s*(?:class|struct)\s+\w")
FORWARD_DECL_RE = re.compile(r"^\s*(?:class|struct)\s+\w[\w:<>,\s]*;\s*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--paths",
        nargs="+",
        default=["src", "include"],
        help="Files or directories to scan.",
    )
    return parser.parse_args()


def normalize_offset(raw: str) -> str:
    return f"0x{raw.lower().removeprefix('0x')}"


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    violations: list[str] = []
    total_markers = 0

    for path in iter_files(args.paths):
        rel = normalize_repo_relative_path(path, repo_root)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, line in enumerate(lines):
            match = VTABLE_MARKER_RE.match(line)
            if match is None:
                continue
            total_markers += 1
            offset = normalize_offset(match.group("offset"))

            # The very next line must be a real class/struct *definition* -- not a
            # forward declaration, comment, or blank line.
            next_line = lines[idx + 1] if idx + 1 < len(lines) else ""
            if not CLASS_DECL_RE.match(next_line) or FORWARD_DECL_RE.match(next_line):
                stripped = next_line.strip()
                if not stripped:
                    reason = "blank line"
                elif stripped.startswith("//"):
                    reason = "comment line (put it above the // VTABLE: line)"
                elif FORWARD_DECL_RE.match(next_line):
                    reason = (
                        "forward declaration (reccmp would name the vtable after this "
                        "type; move the forward decl above the // VTABLE: line)"
                    )
                else:
                    reason = f"found instead: {stripped[:60]!r}"
                violations.append(
                    f"{rel}:{idx + 1}: // VTABLE {offset} not immediately followed by a "
                    f"class/struct definition ({reason})"
                )

    print(f"Scanned // VTABLE annotations: {total_markers}")

    if not violations:
        print("VTABLE annotation gate passed.")
        return 0

    print("VTABLE annotation gate failed:")
    for item in sorted(violations):
        print(f"    - {item}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
