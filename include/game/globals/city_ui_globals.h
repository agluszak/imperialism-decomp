#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern POINT g_ptCityInteriorMinisterModalMessage; // @ 0x6a2c18

extern char s_mcflavor_00696674[];

extern short g_cityProductionReserveByPolicyBand_00696400[4];

extern float g_cityProductionUpgradeRatioThreshold_00696450[4];

extern short g_cityActionCapabilityGroupBySlot_00650670[32];

// Reverse hit-test priority for the 16 city-production building regions.
extern short g_cityBuildingHitTestOrder[16];

// Resource/order-type -> armory recruit-button icon class (TArmoryView::DoStartup 0x4cee20).
extern short g_resourceTypeToUnitClass_00695528[32];

// FourCC tags of the 23 warehouse commodity value controls (TWarehouseView::DoStartup).
extern unsigned int g_awCommodityValueControlTags_00696108[23];

// Per-building offset added to the city-building sound-effect base (3000).
extern short g_cityBuildingSoundCueOffsets[16];

extern "C" {
extern float g_AiDevelopmentResourceBudgetScale_00650758;

extern "C" const char s_SourcePathUCityDialogs_006962E8[];

extern "C" const char s_SourcePathUCityViews_00696650[];

// Assert source-path string for the UCityMinister TU.
extern "C" const char s_SourcePathUCityMinister_006964B0[];

// TCivMgr.cpp — engineer construction cost tables.
extern short g_awEngineerFortBuildCostByLevel[5];

// Civilian work-order rescind refund by cost class.
extern int g_adwCivilianWorkOrderCostByClass[16];

// Four requirement-resource rows for each of the nine university recruitment
// categories. A -1 entry leaves that row empty.
extern int g_anUniversityRequirementIdByRecruitRow[9][4];

extern "C" const char g_szCityProductionUniversityPrefix[];

extern "C" const char g_szCityProductionArmoryPrefix[];

extern "C" const char g_szCityProductionShipyardPrefix[];

} // extern "C"
