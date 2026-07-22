#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern POINT g_ptTechCapabilityModalMessage;          // @ 0x6a57c8


// Per-tech prerequisite pair (tech ids; 0 = none), indexed by tech id. 0x66ac10.
extern short g_aTechItemPrerequisitePairs[34][2];


// Hex-neighbour offset tables (offset-coordinate grid; even/odd rows shift columns
// differently), indexed by direction 0..5. Read by the city-region border/merge passes.
extern const int g_anTechItemPurchaseCostBySlot_0066aae8[34];

extern "C" {
extern int g_nTacticalTileWidthPx_006A5430;

extern int g_nTacticalTileRowHeightPx_006A5434;

extern int g_nTacticalBattlefieldSurfaceWidth_006A5448;

extern int g_nTacticalBattlefieldSurfaceHeight_006A544C;

extern int g_nTacticalUnitSpriteCellWidth_006A5498;

extern int g_nTacticalUnitSpriteCellHeight_006A549C;

extern char g_nForceTacticalBattleViewFlag_006A4758;

// City-order capability rule-table pointer slots written into TTechMgr+0x264 as tech
// unlocks are applied (default at construction, alternates for tech ids 0x0b/0x16).
// 26 (start, end) capability-priority range pairs (see the .cpp note).
extern short g_anCapabilityPriorityRangePairs[53];

extern "C" const char s_SourcePathUTacViews_00699FF4[];

} // extern "C"
