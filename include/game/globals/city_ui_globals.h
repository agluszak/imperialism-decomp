#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern POINT g_ptCityInteriorMinisterModalMessage; // @ 0x6a2c18

extern char s_mcflavor_00696674[];

extern short g_cityProductionReserveByPolicyBand_00696400[4];

extern float g_cityProductionUpgradeRatioThreshold_00696450[4];

extern short g_cityActionCapabilityGroupBySlot_00650670[32];

// Per-building offset added to the city-building sound-effect base (3000).
extern short g_cityBuildingSoundCueOffsets[16];

extern "C" {
// Horizontal inset of each ship icon inside its eight shipyard queue buttons.
extern short g_shipyardQueueIconLeftBySlot[8]; // @ 0x696508

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

// Armory display metrics indexed by the selected TUnitOrder resource type.
extern short g_awArmoryUnitActionPointsByType[30];
extern float g_afArmoryUnitFirepowerByType[30];
extern int g_anArmoryUnitRangeByType[30];
extern float g_fArmoryFirepowerDisplayScale;

extern "C" const char g_szCityProductionUniversityPrefix[];

extern "C" const char g_szCityProductionArmoryPrefix[];

extern "C" const char g_szCityProductionShipyardPrefix[];

} // extern "C"
