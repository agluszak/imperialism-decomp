#!/usr/bin/env python3
"""Enforce recovered MFC-vs-native geometry boundaries in manual game source.

Game-owned geometry uses ``CPoint``/``CRect``.  ``POINT``/``RECT`` remain valid at
verified Win32/MFC library boundaries and in genuinely packed buffers.  Because a
source scanner cannot prove which arbitrary API owns a boundary, this gate enforces
only mechanically sound parts of that policy:

* no unannotated reinterpret/const/C-style casts to a geometry pointer type; VC5's
  ``CPoint`` and ``CRect`` inherit ``tagPOINT`` and ``tagRECT``, so modeled geometry
  crosses real library boundaries by implicit base conversion;
* the curated TView/TControl geometry surface stays on ``CPoint``/``CRect`` after
  recovery, preventing later overrides from drifting back to native structs.

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

# These are recovered game-owned APIs, not Win32/MFC entry points.  Keep this list
# narrow: add a method only after its ownership and geometry domain are established.
POLICY_METHODS: dict[str, dict[str, str]] = {
    "include/game/TView.h": {
        "HandleMouseDown": "CPoint",
        "HandleMouseUp": "CPoint",
        "DoMouseCommand": "CPoint",
        "QueryContentBounds": "CRect",
        "QueryBounds": "CRect",
        "TranslateRectToWindow": "CRect",
        "TranslatePointToParentChain4D": "CPoint",
        "TranslatePointToParentChain4E": "CPoint",
        "LocalToSuperVRect": "CRect",
        "SuperToLocal": "CPoint",
        "ViewToQDPt": "CPoint",
        "ViewToQDRect": "CRect",
        "AddControlPosToPoint": "CPoint",
        "OffsetRectByCachedPos": "CRect",
        "GetAbsolutePosition": "CPoint",
        "GetDrawableQDRect": "CRect",
        "GetQDExtent": "CRect",
        "ApplyBounds": "CRect",
        "PointInBoundsAndActionable": "CPoint",
        "ContainsMouse": "CPoint",
        "GoAwayByUser": "CPoint",
        "MoveByUser": "CPoint",
        "ResizeByUser": "CPoint",
        "ZoomByUser": "CPoint",
        "WindowToLocal": "CPoint",
    },
    "include/game/TControl.h": {
        "BuildInsetContentRect": "CRect",
    },
}

NATIVE_FOR_MFC = {
    "CPoint": re.compile(r"\bPOINT\b"),
    "CRect": re.compile(r"\bRECT\b"),
}


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


def collect_policy_errors(
    repo_root: Path, policy_methods: dict[str, dict[str, str]] = POLICY_METHODS
) -> list[str]:
    errors: list[str] = []
    for rel, methods in policy_methods.items():
        path = repo_root / rel
        text = normalize(path.read_text(encoding="utf-8", errors="ignore"))
        for method, expected in methods.items():
            matches = list(re.finditer(rf"\b{re.escape(method)}\s*\(([^)]*)\)", text))
            if len(matches) != 1:
                errors.append(f"{rel}: expected one declaration of {method}, found {len(matches)}")
                continue
            signature = matches[0].group(0)
            if expected not in signature:
                errors.append(f"{rel}: {method} must use {expected}: {signature}")
            native = NATIVE_FOR_MFC[expected]
            if native.search(signature):
                errors.append(f"{rel}: {method} drifts back to native geometry: {signature}")
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
