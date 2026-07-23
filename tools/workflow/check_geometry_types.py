#!/usr/bin/env python3
"""Enforce recovered MFC-vs-native geometry boundaries in manual game source.

Game-owned geometry uses ``CPoint``/``CRect``.  ``POINT``/``RECT`` remain valid at
verified Win32/MFC library boundaries and in genuinely packed buffers.  Because a
source scanner cannot prove which arbitrary API owns a boundary, this gate enforces
only mechanically sound parts of that policy:

* no unannotated reinterpret/const/C-style casts to a geometry pointer type; VC5's
  ``CPoint`` and ``CRect`` inherit ``tagPOINT`` and ``tagRECT``, so modeled geometry
  crosses real library boundaries by implicit base conversion;
* the recovered TView/TControl geometry surface stays on ``CPoint``/``CRect``:
  every method declared in the policy headers is enumerated from the header text
  itself (self-maintaining — no pinned method list, no build artifacts) and may
  not carry raw ``POINT``/``RECT``/``SIZE`` in its signature unless it is an
  allowlisted, verified Win32 paint-boundary method.

An irreducible packed-resource cast must carry ``GEOMETRY_RAW_BUFFER:`` on the cast
line or one of the preceding three lines.  The explanation is deliberately local and
reviewable; this is not a general-purpose escape hatch for mismodeled fields.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

DEFAULT_PATHS = ("include/game", "src/game")
RAW_BUFFER_MARK = "GEOMETRY_RAW_BUFFER:"
RAW_BUFFER_WINDOW = 3

GEOMETRY_TYPE = r"(?:CPoint|CRect|POINT|RECT)"
CPP_CAST = re.compile(
    rf"\b(?:reinterpret_cast|const_cast)\s*<[^>]*\b{GEOMETRY_TYPE}\b[^>]*>"
)
C_STYLE_CAST = re.compile(rf"\(\s*(?:const\s+)?\b{GEOMETRY_TYPE}\b\s*\*\s*\)")

# Recovered game-owned geometry surfaces.  The method list is DERIVED from these
# headers at gate time (no hand-maintained method table, no build artifacts): every
# method declared in them must use CPoint/CRect/CSize, never raw Win32
# POINT/RECT/SIZE, except for the explicitly allowlisted library-boundary methods
# below.
POLICY_HEADERS = ("include/game/TView.h", "include/game/TControl.h")

# (header, method) pairs allowed to carry raw Win32 geometry in their signature.
# These are verified Win32 paint-boundary surfaces (WM_PAINT clip rects flowing to
# ValidateRect/child paint, and the raw-rect draw primitive) that the previous
# pinned-list gate deliberately left on RECT*.  The gate errors on stale entries,
# so promote a method to CRect by deleting its row here in the same change.
RAW_GEOMETRY_ALLOWLIST: set[tuple[str, str]] = {
    ("include/game/TView.h", "InvalidateCityDialogRectRegion"),
    ("include/game/TView.h", "ValidateControlRectIfWindowActive"),
    ("include/game/TView.h", "PaintVisibleChildrenIntersectingClipRect"),
    ("include/game/TView.h", "Draw"),
    ("include/game/TView.h", "DrawRectangleInCurrentUiContext"),
}

MFC_GEOMETRY = re.compile(r"\b(?:CPoint|CRect|CSize)\b")
RAW_GEOMETRY = re.compile(r"\b(?:LP)?(?:POINT|RECT|SIZE)\b|\bLPCRECT\b")

# One method declaration in comment-stripped, whitespace-normalized header text:
# optional return type / qualifiers, name, non-nested parameter list, optional
# const/override/pure-virtual suffix, terminating semicolon.  The hand-written
# policy headers use no function-pointer or nested-paren parameters, so excluding
# parens from prefix and args keeps macro invocations (DECLARE_DYNCREATE,
# ASSERT_SIZE without trailing text) from swallowing neighbouring declarations.
METHOD_DECL = re.compile(
    r"(?P<prefix>[^;{}()]*)\b(?P<name>~?[A-Za-z_]\w*)\s*\((?P<args>[^;{}()]*)\)\s*"
    r"(?:const\b\s*)?(?:override\b\s*)?(?:=\s*0\s*)?;"
)


def normalize(text: str) -> str:
    return " ".join(text.split())


def collect_geometry_casts(paths, repo_root: Path) -> set[tuple[str, str]]:
    offenders: set[tuple[str, str]] = set()
    for path in iter_files(paths):
        rel = normalize_repo_relative_path(path, repo_root)
        marker_countdown = 0
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
        ):
            norm = normalize(line)
            if RAW_BUFFER_MARK in line:
                marker_countdown = RAW_BUFFER_WINDOW + 1
            documented = marker_countdown > 0
            if marker_countdown > 0:
                marker_countdown -= 1
            if documented:
                continue
            if CPP_CAST.search(line) or C_STYLE_CAST.search(line):
                offenders.add((rel, f"{lineno}:{norm}"))
    return offenders


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def iter_method_declarations(text: str) -> list[tuple[str, str]]:
    """Yield ``(name, signature)`` for each method declared in header text.

    ``signature`` is the declaration's return-type prefix plus parameter list
    (whitespace-normalized), i.e. everything type-bearing except the method name.
    """
    declarations: list[tuple[str, str]] = []
    normalized = normalize(strip_comments(text))
    for match in METHOD_DECL.finditer(normalized):
        signature = normalize(f"{match.group('prefix')} ({match.group('args')})")
        declarations.append((match.group("name"), signature))
    return declarations


def collect_policy_errors(
    repo_root: Path,
    policy_headers: tuple[str, ...] = POLICY_HEADERS,
    allowlist: set[tuple[str, str]] | None = None,
) -> list[str]:
    if allowlist is None:
        allowlist = RAW_GEOMETRY_ALLOWLIST
    errors: list[str] = []
    used_allowlist: set[tuple[str, str]] = set()
    for rel in policy_headers:
        path = repo_root / rel
        if not path.is_file():
            errors.append(f"{rel}: policy header missing — update POLICY_HEADERS")
            continue
        declarations = iter_method_declarations(
            path.read_text(encoding="utf-8", errors="ignore")
        )
        mfc_seen = False
        for name, signature in declarations:
            if MFC_GEOMETRY.search(signature):
                mfc_seen = True
            if RAW_GEOMETRY.search(signature):
                if (rel, name) in allowlist:
                    used_allowlist.add((rel, name))
                    continue
                errors.append(
                    f"{rel}: {name} uses raw Win32 geometry (POINT/RECT/SIZE): "
                    f"{signature}"
                )
        if not mfc_seen:
            errors.append(
                f"{rel}: no CPoint/CRect/CSize method declarations found — "
                "declaration parser or policy scope has drifted"
            )
    for rel, name in sorted(allowlist - used_allowlist):
        if rel in policy_headers:
            errors.append(
                f"{rel}: stale RAW_GEOMETRY_ALLOWLIST entry {name} — no raw-geometry "
                "declaration matches it; delete the allowlist row"
            )
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    casts = sorted(collect_geometry_casts(args.paths, repo_root))
    policy_errors = collect_policy_errors(repo_root)

    if casts or policy_errors:
        print("Geometry-type gate FAILED:")
        for rel, offender in casts:
            print(f"  - {rel}:{offender}")
        for error in policy_errors:
            print(f"  - {error}")
        print("Use CPoint/CRect for modeled game geometry and implicit base conversion at")
        print("real POINT/RECT library boundaries. Annotate only genuine packed buffers with")
        print(f"// {RAW_BUFFER_MARK} <layout evidence>.")
        return 1

    print("Geometry-type gate passed: no cast bridges; curated APIs use MFC geometry types.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
