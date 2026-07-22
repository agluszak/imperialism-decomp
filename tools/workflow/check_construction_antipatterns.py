#!/usr/bin/env python3
"""Gate real-C++-construction anti-patterns in gameplay code.

Enforces the mechanically-checkable subset of the "real C++ construction and
inheritance" Hard Rules in AGENTS.md as a baseline-free HARD BAN: any occurrence
of a tracked pattern in manual source fails the gate. There is no baseline file
and no update escape hatch -- the debt these patterns represent was fully
eradicated, so re-introducing one is always a regression to fix, never to bless.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path, strip_generated_blocks
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Hard Rule 1: no inline assembly.
    ("inline_asm", re.compile(r"\b(?:__asm|_asm)\b|\basm\s*\(")),
    # Construction rule 7: placement-new on this is not base construction.
    ("placement_new_this", re.compile(r"\bnew\s*\(\s*this\s*\)")),
    # Construction rule 2: no manual vtable-pointer writes. Catches the write through
    # `this` (C-style or reinterpret_cast), the same write through ANY object variable,
    # and explicit `obj->vtable = ...` / `obj.vptr = ...` member assignments. To avoid
    # flagging legitimate offset-0 out-param writes (e.g. TFileStream::ReadByte stores a
    # deserialized object pointer), the raw-pointer form requires a vtable-looking RHS:
    # `& <symbol>` or `reinterpret_cast<void*>(0x<const>)`.
    ("manual_vptr_write", re.compile(
        r"\*\s*\(\s*void\s*\*\*\s*\)\s*this\s*="
        r"|\bvptr\s*=\s*g_vtbl"
        r"|\*\s*(?:reinterpret_cast<\s*void\s*\*\*\s*>\s*\(\s*\w+\s*\)|\(\s*void\s*\*\*\s*\)\s*\w+)"
        r"\s*=\s*(?:&|reinterpret_cast<\s*void\s*\*\s*>\s*\(\s*0x)"
        r"|->\s*v(?:f?table|ptr)\s*=\s*(?:reinterpret_cast<\s*void\s*\*\s*>|&)"
        r"|\.\s*v(?:f?table|ptr)\s*=\s*(?:reinterpret_cast<\s*void\s*\*\s*>|&)")),
    # Heuristic note: never reinterpret_cast to a __thiscall function pointer.
    ("thiscall_cast", re.compile(r"reinterpret_cast<[^>]*__thiscall[^>]*>")),
    # Faking a thiscall as __fastcall with a dummy edx second arg (the most-repeated
    # correction in this repo): any function-pointer cast that spells __fastcall, and
    # any fastcall signature whose second parameter is a dummy/edx placeholder.
    ("fastcall_dummy_edx", re.compile(
        r"reinterpret_cast<[^>]*__fastcall[^>]*>"
        r"|__fastcall\s*\*?\s*\w*\s*\)?\s*\([^)]*,\s*(?:int|unsigned int|void\s*\*)\s*"
        r"(?:/\*\s*edx\s*\*/|\bedx\w*|\bunused\w*|\bdummy\w*)")),
    # Function-pointer casts of known symbols in ANY spelling (typedef'd or inline
    # cast to a fn-ptr type): the durable fix is a real method/prototype, not a cast.
    ("fnptr_cast", re.compile(
        r"reinterpret_cast<\s*\w[^>]*\(\s*(?:__cdecl|__stdcall|__fastcall|__thiscall)?\s*\*")),
    # Construction rules 8/16: temporary construction-bridge helper names.
    ("bridge_name", re.compile(r"\b(?:Construct\w*AtThis|VCall_\w*Runtime|\w*AndMaybeFree)\b")),
    # Banned porting approach: class operator new/delete used as a construction factory.
    # Port real methods + real inheritance instead.
    ("operator_new_delete", re.compile(r"\boperator\s+(?:new|delete)\s*\(")),
    # Hard Rule 8: raw byte-offset access through `this` instead of a typed field.
    ("raw_this_offset", re.compile(
        r"reinterpret_cast<\s*(?:unsigned\s+)?char\s*\*\s*>\s*\(\s*this\s*\)\s*\+"
        r"|\(\s*(?:unsigned\s+)?(?:char|BYTE)\s*\*\s*\)\s*this\s*\+")),
)

KEYS = [key for key, _ in PATTERNS]

# Low-level runtime files that may legitimately contain raw construction mechanics,
# documented in-place. Keep this list minimal.
INFRA_ALLOWLIST: set[str] = set()

DEFAULT_EXTENSIONS = {".h", ".hpp", ".c", ".cc", ".cpp"}
GENERATED_MARKERS = ("/ghidra_autogen/", "/autogen/stubs/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", nargs="+", default=["src", "include"], help="Root paths to scan.")
    return parser.parse_args()


def is_generated(rel: str) -> bool:
    return any(marker in f"/{rel}" for marker in GENERATED_MARKERS)


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


def count_patterns(file_path: Path) -> dict[str, int]:
    text = strip_generated_blocks(file_path.read_text(encoding="utf-8", errors="ignore"))
    return {key: len(pattern.findall(text)) for key, pattern in PATTERNS}


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    current: dict[str, dict[str, int]] = {}
    for file_path in collect_files(repo_root, args.roots):
        rel = normalize_repo_relative_path(file_path, repo_root)
        if rel in INFRA_ALLOWLIST or is_generated(rel):
            continue
        counts = count_patterns(file_path)
        if sum(counts.values()) == 0:
            continue
        current[rel] = counts

    if current:
        print("Construction anti-pattern gate failed (hard ban -- zero occurrences allowed):")
        for rel in sorted(current):
            present = ", ".join(k for k in KEYS if current[rel].get(k, 0))
            print(f"  - {rel}: construction anti-pattern(s) [{present}]")
        print("See AGENTS.md 'Hard rules: real C++ construction and inheritance'.")
        print("This is a hard ban with no baseline: fix the source, do not bless it.")
        return 1

    print("Construction anti-pattern gate passed (hard ban -- zero offenders).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
