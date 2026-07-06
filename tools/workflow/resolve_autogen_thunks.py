#!/usr/bin/env python3
"""Rewrite Ghidra jmp-thunk / alias names to real names in src/ghidra_autogen.

Ghidra prints calls through the ILT jmp table and linker jmp stubs under the
*stub's* auto-name (``thunk_Foo``) or under an alias qualified by the target's
class (``TMapDialog::thunk_HandleCityDialogNoOpSlot18``). The bulk decompile
export keeps those raw, so the autogen bodies read against fake symbols even
though the real target is known.

This pass applies the same ``ThunkResolver`` that ``decompile_one`` uses (driven
by ``config/thunk_map.csv``) over the committed
autogen files in place, so promoting from autogen — or just reading it — already
lands on real names (e.g. ``TObject::ReadFrom`` instead of a misnamed thunk).

It is deterministic and idempotent: re-running on already-resolved files is a
no-op. ``src/ghidra_autogen`` is reference-only (not compiled), so this never
changes the build; it only improves the text that promotion copies from.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.common.thunk_names import ThunkResolver, load_thunk_map


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        help="Specific autogen .cpp files to resolve (default: all of --autogen-dir).",
    )
    parser.add_argument("--autogen-dir", default="src/ghidra_autogen")
    parser.add_argument("--thunk-map", default="config/thunk_map.csv")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit non-zero if any file would change (CI/gate mode).",
    )
    return parser.parse_args()


def iter_target_files(repo_root: Path, args: argparse.Namespace) -> list[Path]:
    if args.paths:
        return [resolve_repo_path(repo_root, p) for p in args.paths]
    autogen_dir = resolve_repo_path(repo_root, args.autogen_dir)
    if not autogen_dir.is_dir():
        raise SystemExit(f"Missing autogen directory: {autogen_dir}")
    return sorted(autogen_dir.rglob("*.cpp"))


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    thunk_map = load_thunk_map(resolve_repo_path(repo_root, args.thunk_map))
    resolver = ThunkResolver(thunk_map)
    if not resolver:
        print(f"Empty thunk map ({args.thunk_map}); nothing to resolve.")
        return 0

    files = iter_target_files(repo_root, args)
    changed: list[Path] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        resolved = resolver.resolve(text)
        if resolved != text:
            changed.append(path)
            if not args.check:
                path.write_text(resolved, encoding="utf-8")

    verb = "would change" if args.check else "rewrote"
    print(f"thunk map entries: {len(thunk_map)}")
    print(f"files scanned: {len(files)}")
    print(f"files {verb}: {len(changed)}")

    if args.check and changed:
        for path in changed[:20]:
            print(f"  {path}")
        if len(changed) > 20:
            print(f"  ... and {len(changed) - 20} more")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
