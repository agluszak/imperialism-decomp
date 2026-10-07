#pragma once
#include "game/globals/global_types.h"
#include "game/tactical_ui/TechPrerequisitePair.h"

struct IndustryCapabilityClassSlotEntry {
  int classId;
  int raw[8];
};

extern POINT g_ptTechCapabilityModalMessage;

extern TTechMgr* g_pTechMgr;

// Tactical unit sprite facing offsets: [unit type][orientation][side].
extern POINT g_aTacticalUnitFacingOffsetTable[29][7][2];

// Per-tech prerequisite pair (tech ids; 0 = none), indexed by tech id.
extern TechPrerequisitePair g_aTechItemPrerequisitePairs[34];

extern const int g_anTechItemPurchaseCostBySlot[34];

extern "C" {
extern bool g_nForceTacticalBattleViewFlag;

extern short g_anCapabilityPriorityRangeData[54];

extern "C" char s_SourcePathUTacViews[];

} // extern "C"

extern CSize g_tacticalTileSize;
extern CSize g_tacticalBattlefieldSurfaceSize;
extern CSize g_tacticalUnitSpriteCellSize;
