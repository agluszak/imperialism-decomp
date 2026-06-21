#!/usr/bin/env python3
"""Batch shape-only class generation.

Runs ``gen_class(..., no_bodies=True)`` across every eligible headerless game-class
manifest so each remaining class gets a real C++ header (vtable shape + ``// VTABLE:``
annotation + virtual declarations) and a compilable cpp stub — **without** porting any
Ghidra bodies. Bodies are deferred to a later per-class decomp-loop pass.

Eligibility (a manifest ``config/classes/<Class>.yml`` qualifies when):
  * it has a ``generated:`` block (Family_* pseudo-classes have none → excluded),
  * no ``include/game/<Class>.h`` already exists,
  * the name is not an MFC ``C[A-Z]*`` class (those link real ``nafxcw``), and
  * its base header is *resolvable* — i.e. the immediate base is a source root with a
    header, an already-recovered header, or another class in this batch (computed to a
    fixpoint). Classes whose base would never have a header (e.g. the unmanifested
    ``TFloatWindow`` / ``TNumberText``) are skipped so the batch build can't break.

Ownership is serialized through ``config/function_ownership.csv``: ``gen_class`` claims
slot addresses as it writes each class, so a later class that would claim an
already-owned address is refused (rc != 0). Such refusals — and vtable-annotation
collisions — are logged and skipped; any partially written new files are removed so the
tree is never left half-generated.
"""

from __future__ import annotations

import argparse
import io
import re
from contextlib import redirect_stdout
from pathlib import Path

from tools.common import class_manifest as cm
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.gen_class import gen_class, header_path

MFC_RE = re.compile(r"^C[A-Z]")
# Source-owned roots that already have (or never need) a hand-written header.
SOURCE_ROOTS = {"TObject", "CObject"}


def _already_implemented(repo_root: Path, cls: str) -> bool:
    """True if the class already has a header *or* an existing .cpp (it may be
    implemented inline in the .cpp with no separate header — never clobber it)."""
    if header_path(repo_root, cls).exists():
        return True
    return resolve_repo_path(repo_root, f"src/game/{cls}.cpp").exists()


def _candidate_classes(repo_root: Path) -> dict[str, str]:
    """``class -> immediate base`` for every eligible (pre base-resolvability) class."""
    classes_dir = resolve_repo_path(repo_root, "config/classes")
    out: dict[str, str] = {}
    for path in sorted(classes_dir.glob("*.yml")):
        cls = path.stem
        if cls.startswith("Family_") or MFC_RE.match(cls):
            continue
        if _already_implemented(repo_root, cls):
            continue
        manifest = cm.load_manifest(path)
        gen = manifest.get("generated")
        if not gen:
            continue
        out[cls] = str(gen.get("base") or "")
    return out


def _resolvable(repo_root: Path, candidates: dict[str, str]) -> list[str]:
    """Fixpoint: keep classes whose base will have a header after the batch."""
    have_header = {p.stem for p in resolve_repo_path(repo_root, "include/game").glob("*.h")}
    keep = dict(candidates)
    while True:
        resolvable = set(keep) | have_header | SOURCE_ROOTS
        dropped = {c: b for c, b in keep.items() if b and b not in resolvable}
        if not dropped:
            break
        for c in dropped:
            del keep[c]
    return sorted(keep)


def _skip_reason(output: str) -> str:
    """Pull a human reason out of gen_class's stdout for the skip log."""
    for key in ("refusing", "scaffold issue", "ownership collisions", "already annotated"):
        for line in output.splitlines():
            if key in line:
                return line.strip().lstrip("!").strip()
    return "refused (rc != 0); see output"


def run_batch(repo_root: Path, write: bool, limit: int = 0) -> int:
    candidates = _candidate_classes(repo_root)
    order = _resolvable(repo_root, candidates)
    unresolvable = sorted(set(candidates) - set(order))
    if limit:
        order = order[:limit]

    print(f"gen-classes: {len(candidates)} eligible, {len(order)} generatable, "
          f"{len(unresolvable)} skipped (unresolvable base).")
    if unresolvable:
        print("  unresolvable base (skipped): " + ", ".join(unresolvable))
    if not write:
        print("  (dry-run) pass --write to scaffold these classes (shape-only).")
        for cls in order:
            print(f"    would generate {cls} (base {candidates[cls] or '<root>'})")
        return 0

    generated: list[str] = []
    skipped: list[tuple[str, str]] = []
    for cls in order:
        hpath = header_path(repo_root, cls)
        cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")
        pre_existing = {p for p in (hpath, cpp_path) if p.exists()}

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = gen_class(repo_root, cls, write=True, no_bodies=True)
        out = buf.getvalue()

        if rc != 0:
            # Remove anything this attempt created so the tree stays consistent.
            for p in (hpath, cpp_path):
                if p.exists() and p not in pre_existing:
                    p.unlink()
            skipped.append((cls, _skip_reason(out)))
            continue
        generated.append(cls)

    pruned = _prune_orphans(repo_root, generated)

    print(f"\ngen-classes: generated {len(generated)} class(es); skipped {len(skipped)}; "
          f"pruned {len(pruned)} orphan(s) (base header missing).")
    if pruned:
        print("  pruned: " + ", ".join(sorted(pruned)))
    if skipped:
        print("skipped:")
        for cls, reason in skipped:
            print(f"    {cls}: {reason}")
    return 0


_BASE_RE = re.compile(r"class\s+\w+\s*:\s*public\s+(\w+)")


def _header_base(hpath: Path) -> str | None:
    for line in hpath.read_text(encoding="utf-8").splitlines():
        m = _BASE_RE.match(line)
        if m:
            return m.group(1)
    return None


def _prune_orphans(repo_root: Path, generated: list[str]) -> set[str]:
    """Iteratively remove generated classes whose immediate base header is absent.

    A class skipped at write time (e.g. a vtable-annotation collision) leaves any
    class deriving from it with an unsatisfiable ``#include "game/<Base>.h"``. Remove
    those (and anything transitively deriving from them) so the batch never leaves a
    non-building tree.
    """
    include_dir = resolve_repo_path(repo_root, "include/game")
    pruned: set[str] = set()
    gen_set = set(generated)
    while True:
        have = {p.stem for p in include_dir.glob("*.h")} - pruned | SOURCE_ROOTS
        round_pruned = set()
        for cls in gen_set - pruned:
            base = _header_base(header_path(repo_root, cls))
            if base and base not in have:
                round_pruned.add(cls)
        if not round_pruned:
            break
        for cls in round_pruned:
            for p in (header_path(repo_root, cls),
                      resolve_repo_path(repo_root, f"src/game/{cls}.cpp")):
                if p.exists():
                    p.unlink()
        pruned |= round_pruned
    return pruned


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Batch shape-only class generation (no bodies).")
    p.add_argument("--write", action="store_true", help="Apply (default: dry-run list).")
    p.add_argument("--limit", type=int, default=0, help="Generate at most N classes (0 = all).")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return run_batch(repo_root_from_file(__file__), args.write, args.limit)


if __name__ == "__main__":
    raise SystemExit(main())
