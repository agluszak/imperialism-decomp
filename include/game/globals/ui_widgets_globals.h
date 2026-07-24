#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern char s_szCombatLossesHeading_00699324[];

extern "C" {

extern int g_nOverlayClipCacheParamX;

extern int g_nOverlayClipCacheParamY;

extern const int kTradeSellPropagationTags[17];

extern const int g_tradeBidNationMetricControlTags[24];

extern const unsigned int g_majorTreatyPanelTags[7];

extern const unsigned int g_minorTreatyPanelTags[16];

extern const unsigned int g_majorTreatyCellTags[7];

// 17 (x,y) anchor points used to build the 16 city-building hover/hit-test rects (each a
// fixed 10x10 box at its anchor, except slots 10-11 which span between two consecutive
// anchors), plus a trailing (1,0) pair with no known consumer that shares this data blob.
// 0x696198.
extern short g_anCityBuildingSlotOrder[16];
extern short g_anCityBuildingSlotCoords[36];
extern int g_nCityBuildingSlotXOffsetIndex;
extern int g_nCityBuildingDrawYOffsetIndex;
extern short g_awCityBuildingActionResourceIds[72];
extern RECT g_anCityBuildingLayoutValues[72];

// Per-building-slot hover/hit-test rects (indexed by slotId, see
// TToolBarCluster::HandleCityBuildingHoverSelection), built by
// InitializeCityBuildingHoverSelectionRects_004b95c0. 0x6a2998.
extern CRect g_aCityBuildingHoverSelectionRects[16];

// 41 layout rects for the city-building screen, written component-by-component in
// left/top/right/bottom order by InitializeCityBuildingLayoutData: thirteen groups of
// three rects (the trailing rects of a group are zero when that building has fewer
// hotspots) plus a final pair. 0x6a24e8.
extern CRect g_aCityBuildingLayoutRects[41];

// 31 action-button rects for the city-building screen, placement-constructed by
// InitializeCityBuildingLayoutData (immediately after g_aCityBuildingLayoutRects). 0x6a2778.
extern CRect g_aCityBuildingActionRects[31];

extern "C" const unsigned int g_tradeCommodityRowTagTable[17];

extern "C" const char s_SourcePathUTestDialogs_0069A7F8[];

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp / turn_flow_cooldown.cpp — turn-cooldown state.
extern short g_nTurnCooldownDeferCounter006A43C4;

extern short g_nTurnCooldownSideFlag00698B10;

// TStatusButton.cpp / TCivDescription.cpp — city-dialog legend selection state.
extern void* g_pActiveCityDialogLegendSelectionOwner;

extern int g_bCityDialogLegendSelectionInitialized;

// TCivDescription.cpp — per-civilian-class tile profile / legend selection counts.
extern short g_anTargetTileProfileByCivilianClassAndSlot[];

extern unsigned short g_awCivilianLegendSelectionCountsBySlot[16];

// TArmyToolbar.cpp — maps each of the 30 military-unit types to one of the ten
// toolbar placard/arrow categories.
extern int g_anArmyToolbarCategoryByUnitType[30];

} // extern "C"
