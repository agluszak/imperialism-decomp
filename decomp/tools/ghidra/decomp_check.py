#!/usr/bin/env python3
"""Run ghidra-decompile benchmarks and verify must-keep / should-improve patterns.

Usage:
  uv run python -m tools.ghidra.decomp_check
  uv run python -m tools.ghidra.decomp_check --strict   # fail on missing should-improve too

Exits 0 when all must-keep patterns match; 1 on regression.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass

from tools.common.repo import repo_root_from_file
from tools.ghidra.vtable_struct_check import CHECKS as VTABLE_STRUCT_CHECKS, run_checks as run_vtable_struct_checks

REPO = repo_root_from_file(__file__)


def run_struct_checks() -> list[str]:
    try:
        return run_vtable_struct_checks(VTABLE_STRUCT_CHECKS)
    except Exception as exc:  # noqa: BLE001
        return [f"vtable struct check error: {exc}"]


@dataclass(frozen=True)
class BenchCase:
    addr: int
    label: str
    must_keep: tuple[str, ...]
    should_improve: tuple[str, ...] = ()
    must_not: tuple[str, ...] = ()


# Regression anchors — keep in sync with docs/ghidra-decomp-improvement-plan.md
CASES: tuple[BenchCase, ...] = (
    BenchCase(
        0x00588B70,
        "TIndustryCluster::OrphanLeaf_NoCall_Ins07_004d8920",
        (
            r"g_apNationStates\[.*\]->city",
            r"TCity::GetCityBuildingProductionValueBySlot",
            r"TAmtBarCluster::",
        ),
        (
            r"summaryTags|primaryControlTag",
            r"orderSlotsE4",
        ),
        (r"TCity::TCity::", r"TApplication::TApplication::"),
    ),
    BenchCase(
        0x004CA571,
        "TBuildingConstructionView::OpenCityViewBuildingOrderDialog",
        (
            r"this->pCity",
            r"TCity::GetCityBuildingProductionValueBySlot",
        ),
        (r"orderSlotsE4",),
    ),
    BenchCase(
        0x0057C578,
        "RebuildGlobalOrderManagersAndCapabilityState",
        (
            r"g_pDiplomacyTurnStateManager",
            r"TDiplomacyMgr",
            r"TTradeMgr",
            r"TInterNationEventQueueManager",
        ),
        (r"g_pUiAnimator", r"TAnimator"),
        must_not=(r"DAT_006a43e0",),
    ),
    BenchCase(
        0x0057C8A0,
        "RebuildMapContextAndGlobalMapState",
        (
            r"g_pActiveMapOrderContext",
            r"TOcean",
            r"g_pGlobalMapState",
            r"TMapMgr",
        ),
        (r"nationCount", r"contextArray"),
    ),
    BenchCase(
        0x0049DF00,
        "InitializeGlobalRuntimeSystemsFromConfig",
        (
            r"g_pLocalizationTable",
            r"TSimMgr",
            r"g_pUiRuntimeContext",
            r"UiRuntimeContext",
        ),
        (r"g_pUiViewManager",),
    ),
    BenchCase(
        0x0051794E,
        "ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias",
        (
            r"g_apTerrainTypeDescriptorTable\[",
            r"TCountry",
        ),
        (r"ownerNationSlot", r"ownedRegionList"),
    ),
    BenchCase(
        0x0050C1BF,
        "TMacViewMgr::RefreshCityProductionDetailPanelAndArrowWidgets",
        (
            r"g_apNationStates\[",
            r"g_pLocalizationTable",
        ),
        (
            r"LoadUiStringByCodeGroupAndOffset|vftable\[0x21\]",
            r"needCapA6",
            r"fieldB6",
        ),
    ),
    BenchCase(
        0x004D83C0,
        "SumWeightedNeighborLinkScoreForLinkedNodes",
        (r"__thiscall", r"TCountry"),
        (r"ownedRegionList",),
    ),
    BenchCase(
        0x00496230,
        "SetActiveQuickDrawSurfaceContext",
        (r"g_pActiveQuickDrawSurfaceContext",),
        (r"TQuickDrawSurfaceContext",),
    ),
)


def decompile(addr: int) -> str:
    proc = subprocess.run(
        ["uv", "run", "python", "-m", "tools.ghidra.decompile_one", f"0x{addr:08x}"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"decompile 0x{addr:08x} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def check_patterns(text: str, patterns: tuple[str, ...]) -> list[str]:
    missing: list[str] = []
    for pat in patterns:
        if not re.search(pat, text, re.IGNORECASE):
            missing.append(pat)
    return missing


def find_forbidden(text: str, patterns: tuple[str, ...]) -> list[str]:
    matched: list[str] = []
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            matched.append(pat)
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghidra decompile benchmark gate.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also fail on missing should-improve patterns.",
    )
    args = parser.parse_args()

    failed = False
    improved_pending = 0
    print("Ghidra decompile benchmark check")
    print("=" * 60)

    struct_failures = run_struct_checks()
    if struct_failures:
        print("\nVtable struct checks:")
        for failure in struct_failures:
            print(f"  FAIL  {failure}")
        failed = True
    else:
        print("\nVtable struct checks: ok")

    for case in CASES:
        print(f"\n0x{case.addr:08x}  {case.label}")
        try:
            out = decompile(case.addr)
        except RuntimeError as exc:
            print(f"  FAIL  {exc}")
            failed = True
            continue

        bad = find_forbidden(out, case.must_not)
        if bad:
            print(f"  FAIL  forbidden patterns matched: {bad}")
            failed = True

        missing_keep = check_patterns(out, case.must_keep)
        if missing_keep:
            print(f"  FAIL  must-keep missing: {missing_keep}")
            failed = True
        else:
            print(f"  ok    must-keep ({len(case.must_keep)} patterns)")

        missing_improve = check_patterns(out, case.should_improve)
        if missing_improve:
            improved_pending += len(missing_improve)
            print(f"  note  should-improve still missing: {missing_improve}")
            if args.strict:
                failed = True
        elif case.should_improve:
            print(f"  ok    should-improve ({len(case.should_improve)} patterns)")

    print("\n" + "=" * 60)
    if failed:
        print("RESULT: FAIL")
        return 1
    if improved_pending:
        print(f"RESULT: PASS (with {improved_pending} should-improve items pending)")
    else:
        print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
