#!/usr/bin/env python3
"""Reshape Ghidra ``__thiscall`` member heads in autogen into real C++ methods.

Ghidra prints a member function's definition in its raw ABI form::

    void __thiscall
    TViewMgr::ReadFrom(TViewMgr *this,TStream *stream)

The class, calling convention and explicit ``this`` are all Ghidra-derived data
(the same data a class manifest carries), so we can rewrite the head to the real
C++ member definition without any extra input::

    void TViewMgr::ReadFrom(TStream *stream)

The body keeps working unchanged — ``this->field`` becomes the implicit ``this``.
Only ``__thiscall`` definitions whose *name is class-qualified* (``Cls::Method``)
and whose *first parameter is literally ``this``* are reshaped; everything else
(unqualified thiscall leaves, ``__fastcall``/``__cdecl``/``__stdcall``, calls,
declarations) is left exactly as-is. ``src/ghidra_autogen`` is reference-only, so
this only improves the text that promotion copies; it never affects the build.
Deterministic and idempotent.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path

# Anchor a definition head: a line-leading return type, ``__thiscall``, then a
# class-qualified name (``Cls::Method`` / ``Cls::~Dtor``) up to its ``(``.
_HEAD = re.compile(
    r"(?P<lead>(?:^|\n))"
    r"(?P<ret>[A-Za-z_][\w:*\s&]*?)"
    r"[ \t]+__thiscall[ \t\r\n]+"
    r"(?P<name>[A-Za-z_~]\w*(?:::~?\w+)+)"
    r"[ \t]*\("
)
_THIS_PARAM = re.compile(r"(?:^|[\s*&])this$")


def _matching_paren(text: str, open_idx: int) -> int | None:
    depth = 0
    for j in range(open_idx, len(text)):
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
    return None


def _split_params(s: str) -> list[str]:
    """Top-level comma split that respects (), [] and <> nesting."""
    out: list[str] = []
    depth = 0
    cur = ""
    for ch in s:
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip() or out:
        out.append(cur)
    return [p.strip() for p in out]


def reshape_text(text: str) -> str:
    edits: list[tuple[int, int, str]] = []
    for m in _HEAD.finditer(text):
        open_idx = m.end() - 1
        close_idx = _matching_paren(text, open_idx)
        if close_idx is None:
            continue
        # Confirm this is a definition (next non-space is `{`), not a call/decl.
        k = close_idx + 1
        while k < len(text) and text[k] in " \t\r\n":
            k += 1
        if k >= len(text) or text[k] != "{":
            continue
        params = _split_params(text[open_idx + 1 : close_idx])
        if not params or not _THIS_PARAM.search(params[0]):
            continue
        rest = [p for p in params[1:] if p and p != "void"]
        new_head = f"{m.group('ret').strip()} {m.group('name')}({', '.join(rest)})"
        edits.append((m.start("ret"), close_idx + 1, new_head))

    if not edits:
        return text
    out: list[str] = []
    prev = 0
    for start, end, replacement in edits:
        out.append(text[prev:start])
        out.append(replacement)
        prev = end
    out.append(text[prev:])
    return "".join(out)


def _selftest() -> int:
    cases = [
        (
            "void __thiscall\nTViewMgr::ReadFrom(TViewMgr *this,TStream *stream)\n\n{\n  x;\n}\n",
            "void TViewMgr::ReadFrom(TStream *stream)\n\n{\n  x;\n}\n",
        ),
        (
            "CRuntimeClass * __thiscall TViewMgr::GetClass(TViewMgr *this)\n{\n  return 0;\n}\n",
            "CRuntimeClass * TViewMgr::GetClass()\n{\n  return 0;\n}\n",
        ),
        # unqualified thiscall leaf: left unchanged
        (
            "undefined4 __thiscall SerializeNode(int param_1)\n{\n  y;\n}\n",
            "undefined4 __thiscall SerializeNode(int param_1)\n{\n  y;\n}\n",
        ),
        # a call site (not a definition): left unchanged
        (
            "  foo = bar __thiscall Baz::Qux(p);\n",
            "  foo = bar __thiscall Baz::Qux(p);\n",
        ),
        # no `this` first param: left unchanged
        (
            "void __thiscall A::B(int param_1,undefined4 param_2)\n{\n}\n",
            "void __thiscall A::B(int param_1,undefined4 param_2)\n{\n}\n",
        ),
        # destructor + function-pointer param survives paren-aware split
        (
            "void __thiscall C::~C(C *this,void (*cb)(int))\n{\n}\n",
            "void C::~C(void (*cb)(int))\n{\n}\n",
        ),
    ]
    ok = True
    for src, want in cases:
        got = reshape_text(src)
        if got != want:
            ok = False
            print("FAIL")
            print("  src :", repr(src))
            print("  want:", repr(want))
            print("  got :", repr(got))
    # idempotency
    for src, _ in cases:
        once = reshape_text(src)
        if reshape_text(once) != once:
            ok = False
            print("FAIL idempotency:", repr(src))
    print("selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Autogen .cpp files (default: whole dir).")
    parser.add_argument("--autogen-dir", default="src/ghidra_autogen")
    parser.add_argument("--check", action="store_true", help="Do not write; fail if changes.")
    parser.add_argument("--selftest", action="store_true", help="Run the built-in tests only.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.selftest:
        return _selftest()
    repo_root = repo_root_from_file(__file__)
    if args.paths:
        files = [resolve_repo_path(repo_root, p) for p in args.paths]
    else:
        autogen_dir = resolve_repo_path(repo_root, args.autogen_dir)
        if not autogen_dir.is_dir():
            raise SystemExit(f"Missing autogen directory: {autogen_dir}")
        files = sorted(autogen_dir.rglob("*.cpp"))

    changed: list[Path] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        reshaped = reshape_text(text)
        if reshaped != text:
            changed.append(path)
            if not args.check:
                path.write_text(reshaped, encoding="utf-8")

    verb = "would change" if args.check else "reshaped"
    print(f"files scanned: {len(files)}")
    print(f"files {verb}: {len(changed)}")
    if args.check and changed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
