#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern "C" double g_dMasterVolumeExponentScale;

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
extern short g_anCityBuildingSlotCoords[32];
extern short g_nCityBuildingSlotYOffsetIndex;
extern short g_nCityBuildingDrawXOffsetIndex;
extern short g_nCityBuildingSlotXOffsetIndex;
extern short g_nCityBuildingDrawYOffsetIndex;
extern short g_awCityBuildingActionResourceIds[72];
extern char* g_pCityBuildingHoverEmptyText_0064faa8;
extern CRect g_cityBuildingHoverFallbackRect_006a2980;

// Per-building-slot hover/hit-test rects (indexed by slotId, see
// TToolBarCluster::HandleCityBuildingHoverSelection), built by
// InitializeCityBuildingHoverSelectionRects_004b95c0. 0x6a2998.
extern CRect g_aCityBuildingHoverSelectionRects[16];

// City-building screen control rects: one 72-rect table (3 rects per building/action
// row) populated by InitializeCityBuildingLayoutData -- elements 0..40 by per-field
// stores, elements 41..71 by inlined CRect constructor calls -- and read with a
// row*3+action stride by TCityProductionView::DoPostCreate. 0x6a24e8.
extern CRect g_aCityBuildingLayoutRects[72];

extern "C" const unsigned int g_tradeCommodityRowTagTable[17];

extern "C" const char s_SourcePathUTestDialogs_0069A7F8[];

// Assert source-path string for the USmallViews TU (TTransportPicture and friends).
extern "C" const char s_SourcePathUSmallViews_006992F0[];

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp / turn_flow_cooldown.cpp — turn-cooldown state.
extern short g_nTurnCooldownDeferCounter006A43C4;

extern short g_nTurnCooldownSideFlag00698B10;

// TStatusButton.cpp / TCivDescription.cpp — city-dialog legend selection state.
extern void* g_pActiveCityDialogLegendSelectionOwner;

extern int g_bCityDialogLegendSelectionInitialized;

// TCivDescription.cpp — per-civilian-class tile profile / legend selection counts.
extern short g_anTargetTileProfileByCivilianClassAndSlot[];
extern const int g_anDevelopableResourceTypesByCivilianClass[9][4]; // @ 0x662b98
extern short g_aDeveloperYieldIconAnchors[4][2];                    // @ 0x698fc8
extern short g_anDevelopmentIconStripBaseXByCivilianClass[9];       // @ 0x698fe0

extern unsigned short g_awCivilianLegendSelectionCountsBySlot[16];

// TArmyToolbar.cpp — maps each of the 30 military-unit types to one of the ten
// toolbar placard/arrow categories.
extern int g_anArmyToolbarCategoryByUnitType[30];

} // extern "C"
