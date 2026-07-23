#!/usr/bin/env python3
"""Assign every manual source file to a subsystem via the ORIGINAL module map.

Joins two facts:

1. ``docs/reference/original_module_map.csv`` — the original .cpp module segments
   of the retail binary, recovered from embedded assert-path strings by
   ``just ghidra original-modules`` (tools/ghidra/original_module_map.py).
2. The ``// FUNCTION: IMPERIALISM 0xADDR`` markers in ``src/game/*.cpp`` — each
   owned address falls in exactly one original module segment.

For each source file it reports the distribution of its addresses over original
modules, the dominant module, the proposed subsystem folder (module -> subsystem
table below), and flags files whose addresses span multiple original modules
(candidate ownership mixups — see bead 8mo.13) or land in unsampled tail zones.

usage: uv run python -m tools.analysis.assign_subsystems
           [--module-map docs/reference/original_module_map.csv]
           [--out docs/reference/subsystem_assignment.csv]

Writes the CSV and prints a summary. Pure file analysis; no Ghidra needed.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from tools.common.repo import repo_root_from_file

MARKER_RE = re.compile(r"^//\s*FUNCTION:\s*IMPERIALISM\s+(0x[0-9A-Fa-f]+)", re.MULTILINE)

# Original module -> proposed subsystem folder. Deliberately coarse: folders are
# decided in bead 8mo.6; this table is the evidence-backed starting proposal.
MODULE_SUBSYSTEM = {
    "Ambit.cpp": "app",
    "MainFrm.cpp": "app",
    "Cross/UAmbit.cpp": "app",
    "CDib.cpp": "gfx",
    "QuickDraw.cpp": "gfx",
    "Cross/UDisplayMgr.cpp": "gfx",
    "McAppStream.cpp": "core",
    "ResourceMgr.cpp": "assets",
    "WAssetMgr.cpp": "assets",
    "IncludeView.cpp": "ui_core",
    "McAppUI.cpp": "ui_core",
    "McWindow.cpp": "ui_core",
    "Cross/UGameWindow.cpp": "ui_core",
    "Cross/UIcon.cpp": "ui_core",
    "Cross/UMacViewMgr.cpp": "ui_core",
    "Cross/UViewMgr.cpp": "ui_core",
    "Cross/UViewMgr.more.cpp": "ui_core",
    "Cross/USmallViews.cpp": "ui_widgets",
    "Cross/UTestDialogs.cpp": "ui_widgets",
    "Cross/UOptionViews.cpp": "ui_screens",
    "Cross/USetupScreens.cpp": "ui_screens",
    "Cross/UNewspaper.cpp": "ui_screens",
    "Cross/UHelpMgr.cpp": "ui_screens",
    "Cross/UCheaters.cpp": "debug",
    "DirectPlay.cpp": "net",
    "WNetMgr.cpp": "net",
    "Cross/UMultiplayerMgr.cpp": "net",
    "Cross/UArmyMgr.cpp": "military",
    "Cross/UUnit.cpp": "military",
    "Cross/UMissionSubs.cpp": "military",
    "Cross/UArmyViews.cpp": "military_ui",
    "Cross/UBattleReportViews.cpp": "military_ui",
    "Cross/UDefenseMinister.cpp": "military_ui",
    "Cross/UNavy.cpp": "navy",
    "Cross/UOcean.cpp": "navy",
    "Cross/UOceanViews.cpp": "navy_ui",
    "Cross/UTacPlayer.cpp": "tactical",
    "Cross/UTacViews.cpp": "tactical_ui",
    "Cross/UCity.cpp": "city",
    "Cross/UCityDialogs.cpp": "city_ui",
    "Cross/UCityMinister.cpp": "city_ui",
    "Cross/UCityViews.cpp": "city_ui",
    "Cross/UCountry.cpp": "nation",
    "Cross/UCountryAuto.cpp": "nation",
    "DiplomacyDialogs.cpp": "diplomacy_ui",
    "Cross/UDiplomacyViews.cpp": "diplomacy_ui",
    "Cross/UMap.cpp": "map",
    "Cross/UMapper.cpp": "map",
    "Cross/USuperMap.cpp": "map",
    "Cross/UMapDlog.cpp": "map_ui",
    "Cross/UTradeViews.cpp": "trade_ui",
}


def read_module_map(path: Path):
    """Return sorted [(lo, hi_sampled, hi_exclusive, module)]."""
    segments = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or line.startswith("module|") or line.startswith("sample|"):
            continue
        mod, _n, lo, hi, nxt = line.split("|")  # pipe-split-ok: reads its own generator output, not a config table
        segments.append((int(lo, 16), int(hi, 16), int(nxt, 16) if nxt else 0x7FFFFFFF, mod))
    return sorted(segments)


def classify(addr: int, segments) -> tuple[str, str]:
    """-> (module, confidence) where confidence is sampled|tail|pre_first."""
    if segments and addr < segments[0][0]:
        return "(before first module sample)", "pre_first"
    for lo, hi, nxt, mod in segments:
        if lo <= addr <= hi:
            return mod, "sampled"
        if hi < addr < nxt:
            return mod, "tail"
    return "(unmapped)", "unmapped"


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--module-map", default=str(repo_root / "docs/reference/original_module_map.csv")
    )
    parser.add_argument(
        "--out", default=str(repo_root / "docs/reference/subsystem_assignment.csv")
    )
    args = parser.parse_args()

    segments = read_module_map(Path(args.module_map))
    rows = []
    multi_module = 0
    for src in sorted((repo_root / "src/game").rglob("*.cpp")):
        addrs = [int(a, 16) for a in MARKER_RE.findall(src.read_text(encoding="utf-8"))]
        if not addrs:
            continue
        mods = Counter()
        tails = 0
        for addr in addrs:
            mod, conf = classify(addr, segments)
            mods[mod] += 1
            tails += conf == "tail"
        dominant, dom_n = mods.most_common(1)[0]
        spread = "+".join(f"{m}:{n}" for m, n in mods.most_common())
        subsystem = MODULE_SUBSYSTEM.get(dominant, "")
        flag = "multi_module" if len(mods) > 1 else ""
        multi_module += len(mods) > 1
        rows.append(
            f"{src.name}|{len(addrs)}|{dominant}|{dom_n}|{subsystem}|{tails}|{flag}|{spread}"
        )

    out = Path(args.out)
    out.write_text(
        "file|n_markers|dominant_module|dominant_n|proposed_subsystem|tail_uncertain|flag|module_spread\n"
        + "\n".join(rows)
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {out} ({len(rows)} files; {multi_module} span multiple original modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
