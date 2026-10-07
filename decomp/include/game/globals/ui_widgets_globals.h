#pragma once

#include "game/nation_domain_types.h"
#include "game/globals/global_types.h"

extern "C" char* g_pSmallViewsEmptyText;
extern "C" char* g_pStatusPictureMainSharedText;

extern "C" double g_dMasterVolumeExponentScale;

extern char s_szCombatLossesHeading[];

extern "C" {

extern int g_nOverlayClipCacheParamX;

extern int g_nOverlayClipCacheParamY;

extern const int kTradeSellPropagationTags[17];

extern const int g_tradeBidNationMetricControlTags[24];

extern const unsigned int g_majorTreatyPanelTags[kMajorNationCount];

extern const unsigned int g_minorTreatyPanelTags[kMinorNationCount];

extern const unsigned int g_majorTreatyCellTags[kMajorNationCount];

extern short g_anCityBuildingSlotOrder[16];
extern short g_anCityBuildingSlotCoords[32];
extern short g_nCityBuildingSlotYOffsetIndex;
extern short g_nCityBuildingDrawXOffsetIndex;
extern short g_nCityBuildingSlotXOffsetIndex;
extern short g_nCityBuildingDrawYOffsetIndex;
extern short g_awCityBuildingActionResourceIds[72];
extern char* g_pCityBuildingHoverEmptyText;
extern CRect g_cityBuildingHoverFallbackRect;

extern CRect g_aCityBuildingHoverSelectionRects[16];

extern CRect g_aCityBuildingLayoutRects[72];

extern "C" const unsigned int g_tradeCommodityRowTagTable[17];

extern "C" const char s_SourcePathUTestDialogs[];

// Assert source-path string for the USmallViews TU (TTransportPicture and friends).
extern "C" const char s_SourcePathUSmallViews[];

// TSimMgr_AdvanceGlobalTurnStateMachine.cpp / turn_flow_cooldown.cpp — turn-cooldown state.
extern short g_nTurnCooldownDeferCounter;

extern short g_nTurnCooldownSideFlag;

// TStatusButton.cpp / TCivDescription.cpp — city-dialog legend selection state.
extern void* g_pActiveCityDialogLegendSelectionOwner;

extern int g_bCityDialogLegendSelectionInitialized;

// TCivDescription.cpp — per-civilian-class tile profile / legend selection counts.
extern short g_anTargetTileProfileByCivilianClassAndSlot[];
extern const int g_anDevelopableResourceTypesByCivilianClass[9][4]; // @ 0x662b98
extern short g_aDeveloperYieldIconAnchors[4][2];                    // @ 0x698fc8
extern short g_anDevelopmentIconStripBaseXByCivilianClass[9];       // @ 0x698fe0

extern unsigned short g_awCivilianLegendSelectionCountsBySlot[16];

extern int g_anArmyToolbarCategoryByUnitType[30];

} // extern "C"
