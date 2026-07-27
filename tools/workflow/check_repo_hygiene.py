#!/usr/bin/env python3
"""Reject editor indexes, compiler output, and stray binaries from the tracked tree.

PR #318 untracked 1933 clangd index files that had accumulated under `.cache/` and added
the directory to `.gitignore`. Ignoring a directory only stops the *next* accidental add
of that exact path, though: nothing prevented the same class of artifact arriving under a
different name, and nothing noticed the 1933 files for however long they sat there. This
gate is the missing half -- it makes the property ("no build or editor artifact is
tracked") checkable instead of relying on `.gitignore` coverage being complete.

The rules are deliberately whole-tree rather than diff-scoped. Every category below is at
zero tracked hits today, so the gate can ban them outright and stay green; a diff-scoped
check would silently grandfather anything that slipped in earlier, which is precisely the
failure mode that let the clangd indexes survive. Because the categories are empty, a hit
is unambiguous: something was added that should not have been, and the fix is to untrack
it rather than to widen this list.

Two exemptions are real, and both are vendored third-party material we did not produce:

  vendor/msvc500/fid-generation/    the Ghidra FID build logs (23 .log files) and its
                                   .rep project database (binary .gbf chunks, multiple MB)
  vendor/, LFS-tracked paths        vendored archives and libraries

Large binaries are handled separately from the extension bans. Sizeable *text* files are
normal here -- config/vtable_abi_evidence.json and the Mac evidence crosswalks run to
several MB -- so the size rule only fires on files that are actually binary, are not
LFS-tracked, and live outside vendor/. That combination is currently empty too.

usage: check-repo-hygiene [--max-binary-bytes N]
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from tools.common.repo import repo_root_from_file

# Compiler, linker, interpreter, and editor output. None of these are tracked today.
BANNED_SUFFIXES = {
    ".pyc": "Python bytecode",
    ".pyo": "Python bytecode",
    ".o": "object file",
    ".obj": "object file",
    ".ilk": "MSVC incremental-link state",
    ".idb": "MSVC incremental-compile state",
    ".ncb": "Visual Studio browse database",
    ".suo": "Visual Studio user options",
    ".sdf": "Visual Studio browse database",
    ".exe": "executable",
    ".dll": "shared library",
    ".pdb": "debug database",
}

# Directory names that are caches or dependency trees wherever they appear.
BANNED_DIRECTORIES = {
    ".cache": "editor/clangd index cache",
    "__pycache__": "Python bytecode cache",
    "node_modules": "dependency tree",
    ".mypy_cache": "type-checker cache",
    ".pytest_cache": "test-runner cache",
    ".ruff_cache": "linter cache",
    ".venv": "virtual environment",
    ".idea": "IDE state",
}

# Build trees. `build-msvc500/` is already covered by the generated-integrity gate, but
# repeating it here keeps this gate meaningful when run on its own.
BANNED_PREFIXES = {
    "build-msvc500/": "build output",
    "build/": "build output",
    "dist/": "build output",
}

# Vendored third-party material we did not generate and do not rebuild.
VENDORED_EXEMPT_PREFIXES = ("vendor/msvc500/fid-generation/",)

# Prefixes where a large binary is expected (vendored archives, libraries, Ghidra DBs).
LARGE_BINARY_EXEMPT_PREFIXES = ("vendor/",)

DEFAULT_MAX_BINARY_BYTES = 1 << 20


def tracked_paths(repo_root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or "git ls-files failed")
    return [path for path in proc.stdout.split("\0") if path]


def lfs_tracked_paths(repo_root: Path, paths: list[str]) -> set[str]:
    """Paths whose `filter` attribute is lfs, resolved in one batch."""
    if not paths:
        return set()
    proc = subprocess.run(
        ["git", "check-attr", "--stdin", "-z", "filter"],
        cwd=repo_root,
        input="\0".join(paths),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return set()
    # -z output is a flat NUL-separated stream of (path, attribute, value) triples.
    fields = proc.stdout.split("\0")
    return {
        fields[index]
        for index in range(0, len(fields) - 2, 3)
        if fields[index + 2] == "lfs"
    }


def is_binary(path: Path) -> bool:
    """A NUL byte in the first 8 KiB, the same heuristic git itself uses."""
    try:
        with path.open("rb") as handle:
            return b"\0" in handle.read(8192)
    except OSError:
        return False


def find_offenders(repo_root: Path, max_binary_bytes: int) -> list[tuple[str, str]]:
    paths = tracked_paths(repo_root)
    lfs_paths = lfs_tracked_paths(repo_root, paths)
    offenders: list[tuple[str, str]] = []

    for path in paths:
        if path.startswith(VENDORED_EXEMPT_PREFIXES):
            continue

        posix = Path(path)
        suffix_reason = BANNED_SUFFIXES.get(posix.suffix.lower())
        if suffix_reason is not None:
            offenders.append((path, suffix_reason))
            continue

        directory_reason = next(
            (BANNED_DIRECTORIES[part] for part in posix.parts if part in BANNED_DIRECTORIES),
            None,
        )
        if directory_reason is not None:
            offenders.append((path, directory_reason))
            continue

        prefix_reason = next(
            (reason for prefix, reason in BANNED_PREFIXES.items() if path.startswith(prefix)),
            None,
        )
        if prefix_reason is not None:
            offenders.append((path, prefix_reason))
            continue

        if posix.suffix.lower() == ".log":
            offenders.append((path, "runtime log"))
            continue

        if path in lfs_paths or path.startswith(LARGE_BINARY_EXEMPT_PREFIXES):
            continue
        absolute = repo_root / path
        try:
            size = absolute.stat().st_size
        except OSError:
            continue
        if size > max_binary_bytes and is_binary(absolute):
            kib = size // 1024
            offenders.append((path, f"untracked-by-LFS binary, {kib} KiB"))

    return offenders


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-binary-bytes",
        type=int,
        default=DEFAULT_MAX_BINARY_BYTES,
        help="size above which a non-LFS binary outside vendor/ is rejected",
    )
    args = parser.parse_args()

    repo_root = repo_root_from_file(__file__)
    offenders = find_offenders(repo_root, args.max_binary_bytes)
    if offenders:
        print("Repository hygiene gate failed; these tracked paths are build or editor output:")
        for path, reason in sorted(offenders):
            print(f"  {path}  ({reason})")
        print(
            "\nUntrack them (git rm --cached) and add the pattern to .gitignore. Do not widen\n"
            "the gate's allowlist unless the file is genuinely vendored third-party material."
        )
        return 1

    print("Repository hygiene gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
