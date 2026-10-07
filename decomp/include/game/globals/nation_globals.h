#pragma once

#include "game/nation_domain_types.h"
#include "game/globals/global_types.h"

class TGreatPower;
class TMinor;
class TCountry;

struct AiCityActionCostProfile {
  short primaryMetricCode;
  short primaryMetricMultiplier;
  short secondaryMetricCode;
  short secondaryMetricMultiplier;
  short baseCost;
  short contextBiasSelector;
  short actionId;
};
ASSERT_SIZE(AiCityActionCostProfile, 14);

extern POINT g_ptGreatPowerModalMessage; // @ 0x6a2df0

extern int g_anTechItemResearchCostByTechId[29];

extern TCountry* g_apTerrainTypeDescriptorTable[23];
extern char* g_pszDescriptorDefaultName;

extern "C" const short g_aDiplomacyPlanningQuarterPhaseByNation[kMajorNationCount];

extern "C" {
extern TMinor* g_apSecondaryNationStateSlots[36];

#define g_apNationAuxRuntimeStateSlots (g_apSecondaryNationStateSlots + 7)

extern TGreatPower* g_apNationStates[kMajorNationCount];
} // extern "C"

extern "C" {

extern "C" float g_afNationOrderQueueDivergence[7];

extern "C" float g_afNationOrderQueueDivergenceMirror[7];

extern "C" float g_afNationMobileUnitDivergence[kMajorNationCount];

extern "C" float g_afNationWeightedMilitaryOrderScore[7];

extern "C" float g_afNationCombinedUnitDivergence[kMajorNationCount];

extern "C" float g_afNationMobileUnitScore[kMajorNationCount];

extern float g_afWarNumberByForeignMinister[8];

extern float g_afWarNumberByDefenseMinister[6];

extern float g_afSeekAllianceByForeignMinister[8];

extern float g_afSeekAllianceByDefenseMinister[6];

extern float g_afAcceptAllianceByForeignMinister[8];

extern float g_afAcceptAllianceByDefenseMinister[6];

extern float g_afSeekPeaceByForeignMinister[8];

extern float g_afSeekPeaceByDefenseMinister[6];

extern float g_afAcceptPeaceByForeignMinister[8];

extern float g_afAcceptPeaceByDefenseMinister[6];

extern float g_Iterate_Linked_List_Value; // 0.25f

extern float g_Compute_City_Order_Value; // 0.5f

extern float g_Compute_Advisory_Peer_LookupTable; // -0.5f

extern float g_afAdvisoryMissionTierThresholdByMinisterSkill[5][6];

extern const float g_Compute_Advisory_Zero;

extern float g_Compute_Advisory_Map_Value;

extern double g_Compute_Advisory_MinusSix;

extern double g_Compute_Advisory_MinusHundred;

extern float g_Compute_Advisory_MinusSixFloat;

extern double g_Compute_Advisory_Hundred;

extern double g_Compute_Advisory_OnePointFive;

// Per-order-type sort priority table (slot 0x55 selection sort).
extern short g_anTrackedOrderSortPriorityByType[12];

extern short g_Rebuild_Primary_Nation_Value[5][kNationSlotCount];

extern short g_industryActionCostWeightResCode09[16];

extern short g_industryActionCostWeightResCode08[16];

extern short g_industryActionCostWeightResCode0B[16];

extern short g_industryActionCostWeightResCode03[16];

extern short g_industryActionCostWeightResCode0C[16];

extern short g_cachedAiCityActionNationSlot;

extern short g_cachedAiCityActionTurnTick;

extern float g_cachedAiCityActionContextBias[3];

extern char g_szUCountrySourcePath[];

// Great-power pressure tuning tables (see global_data_tables.cpp for values).
extern "C" const int g_anNationBasePressureByLocale[6];

extern "C" const int g_anGreatPowerPressureMinFloorByLocale[6];

extern "C" const int g_anGreatPowerEscalationSeedByLocale[6];

extern "C" const int g_anGreatPowerPressureRiseCapByLocale[6];

extern "C" const int g_anGreatPowerPressureDecayStepByLocale[6];

extern "C" const int g_anGreatPowerPressureRiseStepByLocale[6];

extern "C" const int g_anGreatPowerCompileThresholdByLocale[6];

extern "C" const int g_anGreatPowerPressureHardAlertThresholdByLocale[6];

extern "C" const int g_anNationStartingTreasuryByLocale[6];

// TAutoGreatPower.cpp — SetTradeOffersFor scaling constants.

extern double g_Evaluate_Advisory_Case11_Value; // 0.5

extern const double g_AiPressureUnsetSentinel;

extern const float g_AiPressureRatioCap;

extern const double g_AiPressureMidpointScale;

extern const float g_AiPressurePeerScale;

extern const double g_MissionScoreZeroThreshold;

extern const double g_MissionEligibilityRatioMargin;
extern float g_ApplyIndexedResourceDeltaScale;
extern const double g_MinisterWeightHalf;
extern const double g_MinisterWeightOne;
extern const double g_BismarckWeightHigh;
extern const double g_BismarckWeightLow;
extern const float g_DefenderMinisterWeight;
extern const double g_BullyWeightLow;
extern const double g_BullyWeightHigh;

extern short g_industryActionCostWeightResCode10[16];
extern AiCityActionCostProfile g_aiCityActionCostProfiles[30];
extern short g_anProvinceNameOrdinalByNationSlot[23];
extern short g_cityPredictedNeedResetResourceIds[3];
extern const float g_PopulationGrowthRateUnder10;
extern const float g_PopulationGrowthRateUnder15;
extern const float g_PopulationGrowthRateUnder20;
extern const float g_PopulationGrowthRateUnder30;
extern const float g_PopulationGrowthRateUnder40;
extern const float g_PopulationGrowthRateUnder60;
extern const float g_PopulationGrowthRateUnder80;
extern const float g_PopulationGrowthRateUnder400;
extern const double g_PopulationGrowthPenaltyPerRetry;
extern const double g_PopulationGrowthMaximumRetryPenalty;
extern const float g_PopulationGrowthRateAtOrAbove400;

} // extern "C"
