#!/usr/bin/env python3
"""Rewrite the lint container's compile_commands.json for host clangd use.

`just lint "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"` produces
build-clang/compile_commands.json with container paths (/imperialism, /build).
This rewrites those to the host checkout and writes ./compile_commands.json at
the repo root, giving clangd/LSP go-to-definition across the manual sources.
Wrapped by `just gen-compile-commands` (which runs the lint configure first).

The database reflects the clang-cl *lint* flavor, not the MSVC500 reccmp build
— good for navigation, never for matching questions.
"""

from __future__ import annotations

import argparse
import json

from tools.common.repo import repo_root_from_file, resolve_repo_path


def rewrite(entries: list[dict], repo_root: str, build_dir: str) -> list[dict]:
    out = []
    for entry in entries:
        rewritten = {
            key: value.replace("/imperialism", repo_root).replace("/build", build_dir)
            for key, value in entry.items()
            if isinstance(value, str)
        }
        out.append(rewritten)
    return out


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lint-build-dir", default="build-clang")
    parser.add_argument("--out", default="compile_commands.json")
    args = parser.parse_args()

    lint_dir = resolve_repo_path(repo_root, args.lint_build_dir)
    src = lint_dir / "compile_commands.json"
    if not src.is_file():
        print(f"Missing {src} — run `just lint \"-DCMAKE_EXPORT_COMPILE_COMMANDS=ON\"` first")
        return 1

    entries = json.loads(src.read_text(encoding="utf-8"))
    rewritten = rewrite(entries, str(repo_root), str(lint_dir))
    out_path = resolve_repo_path(repo_root, args.out)
    out_path.write_text(json.dumps(rewritten, indent=1), encoding="utf-8")
    print(f"Wrote {out_path} ({len(rewritten)} entries, lint flavor)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
