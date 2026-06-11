#!/usr/bin/env python3
"""Repair method declarations/definitions corrupted by thunk migration."""

from __future__ import annotations

import re
from pathlib import Path

from tools.common.repo import repo_root_from_file

# void reinterpret_cast<TView*>(int arg)->NoOpUiLifecycleHook();
METHOD_DECL = re.compile(
    r"^[ \t]*(void|int|short|char|float|unsigned int|void\s*\*)\s+"
    r"reinterpret_cast<([A-Za-z0-9_]+)\*>\(([^)]*)\)->([A-Za-z0-9_]+)\(([^)]*)\)\s*"
    r"(?:=\s*[^;]+)?;\s*\n",
    re.MULTILINE,
)

# void TView::reinterpret_cast<TView*>(int arg)->NoOpUiLifecycleHook() {
METHOD_DEF = re.compile(
    r"^(void|int|short|char|float|unsigned int|void\s*\*)\s+"
    r"([A-Za-z0-9_]+::)reinterpret_cast<([A-Za-z0-9_]+)\*>\(([^)]*)\)->([A-Za-z0-9_]+)\(",
    re.MULTILINE,
)

# void __fastcall reinterpret_cast<TSortedPtrList*>(TSortedPtrList* self)->Method(
BRIDGE_DEF = re.compile(
    r"^[ \t]*(?:// FUNCTION: IMPERIALISM[^\n]*\n)?"
    r"(?:void|undefined4|void\s*\*)\s+(?:__cdecl\s+|__fastcall\s+|__stdcall\s+)?"
    r"reinterpret_cast<([A-Za-z0-9_]+)\*>\([^)]*\)->([A-Za-z0-9_]+)\([^)]*\)\s*\{[^}]*\}\s*\n?",
    re.MULTILINE,
)

BRIDGE_DECL = re.compile(
    r"^[ \t]*(?:void|void\s*\*)\s+(?:__cdecl\s+|__fastcall\s+|__stdcall\s+)?"
    r"reinterpret_cast<([A-Za-z0-9_]+)\*>\([^)]*\)->([A-Za-z0-9_]+)\([^)]*\)\s*;\s*\n",
    re.MULTILINE,
)


def fix_method_decl(match: re.Match[str]) -> str:
    ret = match.group(1)
    first_param = match.group(3).strip()
    method = match.group(4)
    rest_params = match.group(5).strip()
    if first_param and rest_params:
        params = f"{first_param}, {rest_params}"
    elif first_param:
        params = first_param
    else:
        params = rest_params
    return f"  {ret} {method}({params});\n"


def repair_text(text: str) -> str:
    text = METHOD_DECL.sub(fix_method_decl, text)
    text = METHOD_DEF.sub(r"\1 \2\5(", text)
    text = BRIDGE_DEF.sub("", text)
    text = BRIDGE_DECL.sub("", text)
    return text


def main() -> int:
    repo_root = repo_root_from_file(__file__, levels_up=2)
    changed = 0
    for pattern in ("src/game/**/*.cpp", "include/game/**/*.h"):
        for path in repo_root.glob(pattern):
            if "autogen" in str(path):
                continue
            original = path.read_text()
            repaired = repair_text(original)
            if repaired != original:
                path.write_text(repaired)
                changed += 1
                print(f"repaired {path.relative_to(repo_root)}")
    print(f"Repaired {changed} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
