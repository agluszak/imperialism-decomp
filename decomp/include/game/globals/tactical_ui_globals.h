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
extern char g_nForceTacticalBattleViewFlag_006A4758;

// 26 (start, end) capability-priority range pairs followed by two padding shorts.
// Retail anchors the loop cursor at element 1, pair 0's end.
extern short g_anCapabilityPriorityRangeData_0066ABA4[54];

extern "C" const char s_SourcePathUTacViews_00699FF4[];

} // extern "C"

extern CSize g_tacticalTileSize_006A5430;
extern CSize g_tacticalBattlefieldSurfaceSize_006A5448;
extern CSize g_tacticalUnitSpriteCellSize_006A5498;
