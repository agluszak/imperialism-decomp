#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/tactical_ui/TechPrerequisitePair.h"

struct IndustryCapabilityClassSlotEntry {
  int classId;
  int raw[8];
};

extern POINT g_ptTechCapabilityModalMessage; // @ 0x6a57c8

extern TTechMgr* g_pTechMgr;

// Tactical unit sprite facing offsets: [unit type][orientation][side].
extern POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

// Per-tech prerequisite pair (tech ids; 0 = none), indexed by tech id. 0x66ac10.
extern TechPrerequisitePair g_aTechItemPrerequisitePairs[34];

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

// 26 (start, end) capability-priority range pairs (see the .cpp note).
extern short g_anCapabilityPriorityRangePairs[53];

extern "C" const char s_SourcePathUTacViews_00699FF4[];

} // extern "C"
