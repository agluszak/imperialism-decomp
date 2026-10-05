#pragma once
#include "game/globals/global_types.h"

extern "C" TArmyMgr* g_pMapContextActionManager;
#include "game/globals/tactical_ui_globals.h"

struct MappedFlavorTextNationVariantEntry {
  short variantIndex;
  short pad;
};

extern POINT g_ptArmyOrderModalMessage;      // @ 0x6a2318
extern POINT g_ptArmyValidationModalMessage; // @ 0x6a2288

extern short g_aUnitOrderCostProfileByAbilityId[0x1e][7];

extern short g_MapOrderResourceRollWeightTable_0064c5d8[6][6];

extern "C" {

// Per-unit-type military stat records (7 shorts per type, record base 0x695cd2):
// column 0 = category flag (0x10 = counted toward power/cost), column 1 = power/cost
// points. See TMilitaryUnit::GetArmsCarried (0x5c3400).

extern "C" short g_UnitTypeStatTable_0066EB88[30][7];

extern "C" short g_UnitTypeStatDivisorTable_0066ED30[7];

// Cursor resource ids keyed by the military/civilian map state classifiers (12 entries each).
extern short g_mapCursorTokenByStateIndex_00695668[12];

extern short g_civilianMapCursorTokenByStateIndex_00695680[12];

extern unsigned char g_abStackCompositionClassTable[4][4];

extern int g_anFortLevelAttackerPenaltyPercentByLevel[4];

// Per-military-unit-kind blink/boost eligibility flag (0x64c808).
extern unsigned char g_abUnitTypeBlinkEligibilityFlag[kMilitaryUnitKindCount];

extern int g_anWeightClassByOrderType[kMilitaryUnitKindCount]; // 0x64c790

extern short g_anScaledFactorByOrderType[kMilitaryUnitKindCount]; // 0x64c660

extern float g_afPercentEfficiencyByOrderType[kMilitaryUnitKindCount];    // 0x64c6a0
extern float g_afRandomizedMeterDecayByOrderType[kMilitaryUnitKindCount]; // 0x64c718

extern int g_anCountWeightByOrderType[kMilitaryUnitKindCount]; // 0x695578

extern const signed char g_MapContextStaticTable_00695448[0x20];

extern const unsigned char g_MapContextStaticTable_00695428[0x20];

extern char* g_pMiniCivSharedText_0064cb18;

// Assert source-path string for the UArmyMgr TU.
extern "C" const char s_SourcePathUArmyMgr_0069573C[];

extern "C" const char s_SourcePathUArmyViews_00695858[];

extern const float g_MissionOrderDistanceDecayWeightTable_006978c8[6];

extern float g_ArmyMissionDotProductWeights_00697980[5];

extern float g_ArmyMissionCandidateScoreTable_006978f8[24];

extern const float g_InvadeMissionSuppressedPriorContributionScale_0065A95C;

extern const double g_Recompute_Nation_Order_LookupTable_0065A9E0;
extern short g_nArmsBasicResourceOfferSplitCount_006a3a54;
extern short g_nArmsAdvancedResourceOfferSplitCount_006a3a58;
extern IndustryCapabilityClassSlotEntry g_aIndustryCapabilityClassSlotTable[14];
extern const float g_AttackProvinceMissionReadinessThreshold_0065A8F0;
extern const float g_DefendProvinceMissionCrossSupportFloorScale_0065A8F8;
extern const float g_NavyMissionIndustrialCostWeights_0065A910[4];
extern const float g_NavyMissionQueuedWeightDeficitScale_0065A958;
extern const float g_NavyMissionSimilarityExcessBlend_0065A960;
extern const float g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel_0065A968[5][4];
extern const float g_Recompute_Nation_Order_LookupTable_0065A9BC;
extern const float g_Recompute_Nation_Order_LookupTable_0065A9C4;
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern const float g_MissionPositiveFallback_0065A9B8;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern const double g_PortZoneFriendlyMissionScoreMultiplier_0065AA10;
extern const double g_PortZoneForeignMissionScoreMultiplier_0065AA18;
extern const float g_Recompute_Nation_Order_LookupTable_0065AA20;
extern const double g_ArmyMissionEligibleUnitStrengthScale_0065AA48;
extern const float g_MissionResourceWeightScale_0065A8FC;
extern const float g_BlockadePortMissionThreatFloor_0065A900;
extern const float g_NavyMissionIndustrialCostWeights_0065A910[4];
extern const float g_BlockadePortMissionThreatScale_0065A904;
extern const float g_MissionEmptyResourceWeight_0065AA24;
extern const double g_BeachheadMissionPriorityNormalization_0065AA30;

} // extern "C"
