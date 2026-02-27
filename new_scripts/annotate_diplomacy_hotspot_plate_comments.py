#!/usr/bin/env python3
"""
Set/refresh plate comments for key diplomacy hotspot functions (raw semantics only).
"""

from __future__ import annotations

from pathlib import Path

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

COMMENTS = {
    "ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode": (
        "Validates raw diplomacy action code against nation pair and context state.\n"
        "Observed action switch cases: 2,3,4,5,6,7,8,9,10,11,14,15.\n"
        "Writes reject/status code to this+0x636 on failure.\n"
        "Do not assign semantic names to action codes here without external evidence."
    ),
    "ResolveDiplomacyActionFromClickAndUpdateTarget": (
        "Resolves clicked diplomacy target nation slot for current action context.\n"
        "Skips when current raw action state at this+0x25 is 5.\n"
        "Target nation slot is written to this+0xC2 (or -1 when not found).\n"
        "Self-target early return is suppressed only when raw action state this+0x2F is 13."
    ),
    "BuildNationActionOptionCardsFromRelationTable": (
        "Builds nation action-option card entries from bilateral relation records and fallback templates.\n"
        "Observed gating on raw record/action ranges (e.g. <5, >0x15) and special handling around 0x0E..0x11.\n"
        "Treat these constants as raw code-space until mapped to verified gameplay semantics."
    ),
    "ProcessDiplomacyTurnStateEventStateMachine": (
        "Primary diplomacy turn-state event dispatcher.\n"
        "Contains switch-driven transitions and many packet/UI side-effect calls.\n"
        "Use this as the root for mapping raw diplomacy action/relation constants to concrete outcomes."
    ),
    "HandleNationStatusDialogCommand": (
        "Nation-status dialog command router.\n"
        "Dispatches button/tag commands and triggers per-slot state replacement/event emissions.\n"
        "Control tags are raw FourCC values (EControlTagFourCC), not semantic equivalents."
    ),
}


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        fm = program.getFunctionManager()
        by_name = {}
        fit = fm.getFunctions(True)
        while fit.hasNext():
            f = fit.next()
            by_name[f.getName()] = f
        tx = program.startTransaction("Annotate diplomacy hotspot plate comments")
        ok = skip = miss = 0
        try:
            for name, comment in COMMENTS.items():
                fn = by_name.get(name)
                if fn is None:
                    miss += 1
                    print(f"[miss] {name}")
                    continue
                prev = fn.getComment() or ""
                if prev == comment:
                    skip += 1
                    continue
                fn.setComment(comment)
                ok += 1
                print(f"[set] {fn.getEntryPoint()} {name}")
        finally:
            program.endTransaction(tx, True)

        program.save("annotate diplomacy hotspot plate comments", None)
        print(f"[done] ok={ok} skip={skip} miss={miss}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
