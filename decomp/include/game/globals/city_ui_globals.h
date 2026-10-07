#pragma once
#include "game/globals/global_types.h"

extern POINT g_ptCityInteriorMinisterModalMessage;

extern short g_cityProductionReserveByPolicyBand[4];

// Need-type indices applied by TInteriorMinister::SetCityPolicies.
extern short g_aInteriorMinisterNeedPriorityOrder[10];

extern float g_cityProductionUpgradeRatioThreshold[4];

extern short g_cityActionCapabilityGroupBySlot[32];

// Per-building offset added to the city-building sound-effect base (3000).
extern short g_cityBuildingSoundCueOffsets[16];

extern "C" {
// Horizontal inset of each ship icon inside its eight shipyard queue buttons.
extern short g_shipyardQueueIconLeftBySlot[8];

extern float g_AiDevelopmentResourceBudgetScale;

extern "C" const char s_SourcePathUCityDialogs[];

// Assert source-path string for the UCityMinister TU.
extern "C" const char s_SourcePathUCityMinister[];

// TCivMgr.cpp — engineer construction cost tables.
extern short g_awEngineerFortBuildCostByLevel[5];

// Civilian work-order rescind refund by cost class.
extern int g_adwCivilianWorkOrderCostByClass[16];

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
