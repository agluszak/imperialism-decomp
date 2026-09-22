#!/usr/bin/env python3
"""Reject `just <recipe>` citations and literal recipe paths that do not resolve.

Docs and tool docstrings hand agents commands; a renamed recipe leaves a dead
command that fails only when someone follows it (construction.md once told
readers to run `just regen-stubs` and `just sync-ownership`, both long gone).
Likewise a recipe naming an explicit tracked path rots silently when the file
moves (scalar-clang-tidy once listed five pre-subsystem-split paths).

Two checks, both cheap and whole-tree:

  * every backtick-quoted `` `just ...` `` span in tracked docs, tool
    docstrings, configs, and justfiles must name a real recipe. Leading
    `NAME=value` variable overrides and `--flags` are skipped; a span with no
    recipe token at all (`just --list`) is not a recipe citation.
  * every literal `src/`, `include/`, `config/`, `docs/`, `tools/`, `tests/`
    path token in a recipe body must exist. Comment lines and lines asserting
    absence (`test ! -e`, `! -f`) are skipped; `{{variable}}` templates are
    not literal paths.

usage: check-just-refs
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file

JUSTFILES = ("justfile", "just")

# name: at column 0, optionally followed by params (defaults contain `=`),
# ending the header with ':'. `x := y` assignments fail the `(?!=)` lookahead.
RECIPE_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_-]*)[^\n:]*:(?!=)")
JUST_SPAN_RE = re.compile(r"`just ([^`]+)`")
# Tracked text files worth scanning for command citations.
SCAN_SUFFIXES = {".md", ".py", ".yml", ".yaml", ".txt", ".just", "justfile"}
# Literal repo paths inside recipe bodies. The lookbehind keeps `tests/`
# from matching inside `build-runtime-tests/`.
PATH_TOKEN_RE = re.compile(
    r"(?<![\w.-])((?:src|include|config|docs|tools|tests)/[\w./-]+)"
)
# Lines that assert a path is absent rather than consume it.
ABSENCE_GUARD_RE = re.compile(r"test\s+!|!\s*-[efd]")


def recipe_names(repo_root: Path) -> set[str]:
    names: set[str] = set()
    for justfile in [repo_root / "justfile", *sorted((repo_root / "just").glob("*.just"))]:
        for line in justfile.read_text(encoding="utf-8").splitlines():
            match = RECIPE_RE.match(line)
            if match:
                names.add(match.group(1))
    return names


def cited_recipe(span: str) -> str | None:
    """First token of a `just ...` span that can be the recipe, or None."""
    for token in span.split():
        if token.startswith("-") or "=" in token or "{" in token or "}" in token:
            continue
        return token.strip("\"'")
    return None


def main() -> int:
    repo_root = repo_root_from_file(__file__, levels_up=2)
    recipes = recipe_names(repo_root)

    proc = subprocess.run(
        ["git", "ls-files"], cwd=repo_root, check=True, capture_output=True, text=True
    )
    tracked = proc.stdout.splitlines()

    errors: list[str] = []

    for rel in tracked:
        path = repo_root / rel
        if path.suffix not in SCAN_SUFFIXES and path.name != "justfile":
            continue
        if (
            "/build" in f"/{rel}"
            or "/vendor/" in f"/{rel}"
            or "/.agents/" in f"/{rel}"
            or rel == "tools/workflow/check_just_refs.py"
        ):
            # This file's docstring legitimately cites dead commands as the
            # historical motivation, and its source holds the match patterns.
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in JUST_SPAN_RE.finditer(text):
            recipe = cited_recipe(match.group(1))
            if recipe is None:
                continue
            if recipe.endswith("*"):
                if not any(name.startswith(recipe[:-1]) for name in recipes):
                    errors.append(f"{rel}: `just {match.group(1)}` matches no recipe")
            elif recipe not in recipes:
                line_no = text.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{rel}:{line_no}: `just {match.group(1)}` names unknown recipe {recipe!r}"
                )

    for justfile in [repo_root / "justfile", *sorted((repo_root / "just").glob("*.just"))]:
        rel = justfile.relative_to(repo_root).as_posix()
        for line_no, line in enumerate(
            justfile.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = line.strip()
            if stripped.startswith("#") or ABSENCE_GUARD_RE.search(line):
                continue
            for match in PATH_TOKEN_RE.finditer(line):
                token = match.group(1).rstrip(".,:;)")
                if "{" in token or "}" in token:
                    continue
                if not (repo_root / token).exists():
                    errors.append(f"{rel}:{line_no}: recipe path {token} does not exist")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"just-reference gate passed ({len(recipes)} recipes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
