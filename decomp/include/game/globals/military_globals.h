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

extern short g_MapOrderResourceRollWeightTable[6][6];

extern "C" {

// Per-unit-type military stats (7 shorts per type): column 0 flags power/cost units,
// column 1 holds their power/cost points.

extern "C" short g_UnitTypeStatTable[30][7];

extern "C" short g_UnitTypeStatDivisorTable[7];

// Cursor resource ids keyed by the military/civilian map state classifiers (12 entries each).
extern short g_mapCursorTokenByStateIndex[12];

extern short g_civilianMapCursorTokenByStateIndex[12];

extern unsigned char g_abStackCompositionClassTable[4][4];

extern int g_anFortLevelAttackerPenaltyPercentByLevel[4];

// Per-military-unit-kind blink/boost eligibility flag.
extern unsigned char g_abUnitTypeBlinkEligibilityFlag[kMilitaryUnitKindCount];

extern int g_anWeightClassByOrderType[kMilitaryUnitKindCount]; // 0x64c790

extern short g_anScaledFactorByOrderType[kMilitaryUnitKindCount]; // 0x64c660

extern float g_afPercentEfficiencyByOrderType[kMilitaryUnitKindCount];    // 0x64c6a0
extern float g_afRandomizedMeterDecayByOrderType[kMilitaryUnitKindCount]; // 0x64c718

extern int g_anCountWeightByOrderType[kMilitaryUnitKindCount]; // 0x695578

extern const signed char g_MapContextStaticTable_00695448[0x20];

extern const unsigned char g_MapContextStaticTable_00695428[0x20];

extern char* g_pMiniCivSharedText;

// Assert source-path string for the UArmyMgr TU.
extern "C" const char s_SourcePathUArmyMgr[];

extern "C" const char s_SourcePathUArmyViews[];

extern const float g_MissionOrderDistanceDecayWeightTable[6];

extern float g_ArmyMissionDotProductWeights[5];

extern float g_ArmyMissionCandidateScoreTable[24];

extern const float g_InvadeMissionSuppressedPriorContributionScale;

extern short g_nArmsBasicResourceOfferSplitCount;
extern short g_nArmsAdvancedResourceOfferSplitCount;
extern IndustryCapabilityClassSlotEntry g_aIndustryCapabilityClassSlotTable[14];
extern const float g_AttackProvinceMissionReadinessThreshold;
extern const float g_DefendProvinceMissionCrossSupportFloorScale;
extern const float g_NavyMissionIndustrialCostWeights[4];
extern const float g_NavyMissionQueuedWeightDeficitScale;
extern const float g_NavyMissionSimilarityExcessBlend;
extern const float g_AttackProvinceMissionResourceScaleByDifficultyAndFortLevel[5][4];
extern const float g_MissionPositiveFallback;
extern const double g_PortZoneFriendlyMissionScoreMultiplier;
extern const double g_PortZoneForeignMissionScoreMultiplier;
extern const double g_ArmyMissionEligibleUnitStrengthScale;
extern const float g_MissionResourceWeightScale;
extern const float g_BlockadePortMissionThreatFloor;
extern const float g_NavyMissionIndustrialCostWeights[4];
extern const float g_BlockadePortMissionThreatScale;
extern const float g_MissionEmptyResourceWeight;
extern const double g_BeachheadMissionPriorityNormalization;

} // extern "C"
