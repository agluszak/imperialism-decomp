#!/usr/bin/env python3
"""Gate: every explicit destructor is placed where its original evidence puts it.

Class-recovery commits keep moving destructors between headers and implementation
files. There are exactly three legitimate shapes, decided by what the original
binary contains for the class:

``standalone``
    ``config/original_entities.csv`` has a ``Class::~Class`` entity, so VC5 emitted
    a real out-of-line destructor body. Defined out of line in ``src/game`` it pairs
    through the mangled ``??1`` symbol with no marker needed. Defined inline in a
    header it only pairs if some marker in the tree claims that address -- otherwise
    a real body silently goes unscored, which is a failure.

``inline_proven``
    The definition carries a ``// FUNCTION:`` marker for the original address, so
    reccmp scores it there. Header and ``.cpp`` are both legitimate homes; the
    marker is what makes the placement provable either way.

``compiler_generated``
    The class only has a ``??_G``/``??_E`` scalar deleting destructor in the binary
    (claimed with ``// SYNTHETIC:`` + the exact backtick name). The explicit
    ``~Class() {}`` exists solely so the polymorphic class emits that helper; it is
    correct, and this gate deliberately does not ask for it to be deleted.

Anything else is an ``unjustified`` destructor: an explicit empty body with no
standalone entity, no inline marker, and no scalar-deleting-destructor claim for
the class. Those are pure source noise -- the implicit destructor compiles to the
same thing -- and the gate fails on them.

The gate never invents empty destructors: a class with no explicit destructor at
all is simply not a subject. It only judges destructors that already exist.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

# `Class::~Class() {` / `Class::~Class() {}` at the start of a line in a .cpp.
CPP_DTOR_RE = re.compile(r"^(?P<cls>\w+)::~(?P<name>\w+)\s*\(\s*\)")
# `~Class() {...}` or `virtual ~Class() override;` inside a class body.
HDR_DTOR_RE = re.compile(r"^\s*(?:virtual\s+)?~(?P<name>\w+)\s*\(\s*\)\s*(?P<tail>.*)$")
MARKER_RE = re.compile(
    r"//\s*(?P<kind>FUNCTION|SYNTHETIC)\s*:\s*\w+\s+0x(?P<addr>[0-9a-fA-F]+)"
)


def canonical_addr(value: str) -> str:
    raw = (value or "").strip().lower().removeprefix("0x")
    return f"{int(raw, 16):x}" if raw else ""


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--symbols-csv",
        default=str(repo_root / "config" / "original_entities.csv"),
        help="Path to original_entities.csv (pipe-delimited).",
    )
    parser.add_argument(
        "--paths", nargs="+", default=["src", "include"], help="Files or directories to scan."
    )
    parser.add_argument(
        "--report", action="store_true", help="Print the full classification, not just failures."
    )
    return parser.parse_args()


def load_class_evidence(csv_path: Path) -> tuple[dict[str, str], set[str]]:
    """Return ({class: address of its standalone ~Class body}, {classes with a ??_G})."""
    standalone: dict[str, str] = {}
    scalar_deleting: set[str] = set()
    if not csv_path.exists():
        return standalone, scalar_deleting
    _fieldnames, rows = read_pipe_table(csv_path)
    for row in rows:
        name = (row.get("name") or "").strip()
        if "::" not in name:
            continue
        cls, _, member = name.partition("::")
        if member.startswith("~"):
            standalone[cls] = canonical_addr(row.get("address") or "")
        elif member == "`scalar deleting destructor'":
            scalar_deleting.add(cls)
    return standalone, scalar_deleting


def collect_claimed_addresses(paths: list[str]) -> set[str]:
    """Every address any // FUNCTION:/// SYNTHETIC: marker in the tree already claims."""
    claimed: set[str] = set()
    for path in iter_files(paths):
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = MARKER_RE.search(line)
            if match is not None:
                claimed.add(canonical_addr(match.group("addr")))
    return claimed


def preceding_marker(lines: list[str], index: int) -> tuple[str, str] | None:
    """Nearest FUNCTION/SYNTHETIC marker in the comment block directly above `index`."""
    cursor = index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if not stripped:
            cursor -= 1
            continue
        if not stripped.startswith("//"):
            return None
        match = MARKER_RE.search(stripped)
        if match is not None:
            return match.group("kind"), canonical_addr(match.group("addr"))
        cursor -= 1
    return None


def body_is_empty(lines: list[str], index: int) -> bool:
    """True when the destructor definition starting at `index` has an empty body."""
    text = lines[index]
    if "{" not in text:
        # `~Class();` — a declaration, not a definition.
        return False
    if "{}" in text.replace(" ", ""):
        return True
    depth = text.count("{") - text.count("}")
    cursor = index + 1
    while cursor < len(lines) and depth > 0:
        stripped = lines[cursor].strip()
        depth += lines[cursor].count("{") - lines[cursor].count("}")
        if stripped and not stripped.startswith("//") and stripped != "}":
            return False
        cursor += 1
    return True


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    standalone, scalar_deleting = load_class_evidence(Path(args.symbols_csv))
    claimed = collect_claimed_addresses(args.paths)

    violations: list[str] = []
    counts = {"standalone": 0, "inline_proven": 0, "compiler_generated": 0}
    rows: list[str] = []

    for path in iter_files(args.paths):
        rel = normalize_repo_relative_path(path, repo_root)
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        is_header = path.suffix in (".h", ".hpp", ".hh", ".hxx")
        for idx, line in enumerate(lines):
            if is_header:
                match = HDR_DTOR_RE.match(line)
                if match is None or "{" not in match.group("tail"):
                    continue  # declaration-only: the .cpp definition is the subject
                cls = match.group("name")
            else:
                match = CPP_DTOR_RE.match(line)
                if match is None or match.group("cls") != match.group("name"):
                    continue
                cls = match.group("cls")

            marker = preceding_marker(lines, idx)
            marker_kind = marker[0] if marker else None
            empty = body_is_empty(lines, idx)

            if marker_kind == "FUNCTION":
                # The definition names the original address it reproduces, so reccmp
                # scores it there -- header or .cpp are both legitimate homes.
                kind = "inline_proven"
            elif cls in standalone:
                # VC5 emitted a real ~Class body. Out of line in a .cpp it pairs through
                # the mangled ??1 symbol; inline in a header it only pairs if some marker
                # in the tree claims that address, otherwise the real body goes unscored.
                kind = "standalone"
                if is_header and standalone[cls] not in claimed:
                    violations.append(
                        f"{rel}:{idx + 1}: {cls} has a standalone ~{cls} body at "
                        f"0x{standalone[cls]} but its definition is inline in a header and no "
                        f"marker claims that address, so the body is never scored. Move it to "
                        f"src/game or claim the address."
                    )
            elif cls in scalar_deleting:
                kind = "compiler_generated"
            elif not empty:
                # A non-empty destructor with real teardown work: the class model says
                # members need releasing even though no original entity is named for it
                # (typically inlined into every caller). Not this gate's business.
                kind = "inline_proven"
            else:
                violations.append(
                    f"{rel}:{idx + 1}: ~{cls} is an empty destructor with no standalone "
                    f"original body, no inline // FUNCTION: marker, and no scalar deleting "
                    f"destructor for {cls}; the implicit destructor is identical. Delete it."
                )
                continue

            counts[kind] += 1
            rows.append(f"{kind:19s} {rel}:{idx + 1}  ~{cls}")

    if args.report:
        for row in sorted(rows):
            print(row)

    total = sum(counts.values())
    print(
        f"Destructor placement: {total} explicit destructors "
        f"({counts['standalone']} standalone, {counts['inline_proven']} inline-proven, "
        f"{counts['compiler_generated']} compiler-generated)."
    )
    if violations:
        print("Destructor placement gate failed:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("Destructor placement gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
