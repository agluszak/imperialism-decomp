#!/usr/bin/env python3
"""Report `// VTABLE:` annotations that reccmp does NOT turn into a matched vtable.

A `// VTABLE:` annotation is only useful if reccmp (a) ingests it as a VTABLE entity and
(b) pairs it with the recompiled vtable. This tool loads the live reccmp compare DB and,
for every `// VTABLE:` annotation in the source, classifies the outcome:

  - matched       : paired with the recomp vtable (the goal).
  - recomp-missing : the orig vtable entity exists but the recompiled binary emits no
                     vtable for this class -- usually because the class is not modeled
                     with real inheritance / a defined key virtual yet (construction
                     scaffolding, all-stub virtuals, never instantiated). Class-modeling
                     work, not an annotation bug. Reported as a WARNING.
  - overridden    : the annotation address is claimed by a non-VTABLE entity (e.g. a
                    `global` row in symbols.csv), so reccmp dropped the VTABLE entity.
                    This is a hard bug -- `just vtable-collision-gate` should catch it.
  - not-ingested  : reccmp produced no entity at the address at all.

Unlike the static gates, this needs the built binary + reccmp DB, so it lives in its own
`just vtable-coverage` target rather than the fast `just gates` bundle.

Exit code: 0 if every annotation is matched-or-recomp-missing; 1 if any annotation is
`overridden` or `not-ingested` (or with --strict, if any are unmatched at all).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from reccmp.compare import Compare
from reccmp.project.detect import RecCmpProject
from reccmp.types import EntityType, ImageId

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

VTABLE_MARKER_RE = re.compile(
    r"^\s*//\s*VTABLE\s*:\s*(?P<module>[A-Za-z0-9_]+)\s+(?P<offset>(?:0x)?[0-9a-fA-F]+)"
)


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--paths",
        nargs="+",
        default=[str(repo_root / "src"), str(repo_root / "include")],
        help="Files or directories to scan for // VTABLE: annotations.",
    )
    parser.add_argument(
        "--project-dir",
        default=str(repo_root),
        help="Directory containing reccmp-project.yml / reccmp-build.yml.",
    )
    parser.add_argument(
        "--target",
        default="IMPERIALISM",
        help="reccmp target id.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail (exit 1) if ANY annotation is unmatched, including recomp-missing.",
    )
    return parser.parse_args()


def collect_annotations(paths: list[str], repo_root: Path) -> dict[int, str]:
    """addr(int) -> 'rel:line' for every // VTABLE: annotation."""
    out: dict[int, str] = {}
    for path in iter_files(paths):
        rel = normalize_repo_relative_path(path, repo_root)
        for idx, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines()):
            m = VTABLE_MARKER_RE.match(line)
            if m is None:
                continue
            addr = int(m.group("offset").lower().removeprefix("0x"), 16)
            out.setdefault(addr, f"{rel}:{idx + 1}")
    return out


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)

    annotations = collect_annotations(args.paths, repo_root)

    project = RecCmpProject.from_directory(Path(args.project_dir))
    target = project.get(args.target)
    engine = Compare.from_target(target)
    db = engine._db  # noqa: SLF001 -- read-only entity inspection

    matched: list[int] = []
    recomp_missing: list[int] = []
    overridden: list[tuple[int, str]] = []
    not_ingested: list[int] = []

    for addr in sorted(annotations):
        ent = db.get(ImageId.ORIG, addr)
        if ent is None:
            not_ingested.append(addr)
            continue
        if ent.get("type") != EntityType.VTABLE:
            overridden.append((addr, str(ent.get("type"))))
            continue
        if ent.recomp_addr is not None:
            matched.append(addr)
        else:
            recomp_missing.append(addr)

    total = len(annotations)
    print(f"// VTABLE: annotations: {total}")
    print(f"  matched (paired with recomp vtable): {len(matched)}")
    print(f"  recomp-missing (no recomp vtable; needs class modeling): {len(recomp_missing)}")
    print(f"  overridden (non-VTABLE entity at address -- BUG): {len(overridden)}")
    print(f"  not-ingested (no reccmp entity at address -- BUG): {len(not_ingested)}")

    if recomp_missing:
        print("\nWARNING: annotations with no recompiled vtable (model the class with real "
              "inheritance + a defined key virtual so MSVC emits the vtable):")
        for addr in recomp_missing:
            print(f"    - 0x{addr:08x}  {annotations[addr]}")

    if overridden:
        print("\nERROR: annotation address claimed by a non-VTABLE entity "
              "(run `just vtable-collision-gate`):")
        for addr, typ in overridden:
            print(f"    - 0x{addr:08x}  {annotations[addr]}  (entity type={typ})")

    if not_ingested:
        print("\nERROR: annotation produced no reccmp entity (malformed annotation?):")
        for addr in not_ingested:
            print(f"    - 0x{addr:08x}  {annotations[addr]}")

    hard_failures = bool(overridden or not_ingested)
    if args.strict and (recomp_missing or hard_failures):
        return 1
    return 1 if hard_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
