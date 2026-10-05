#pragma once
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
extern char* g_pszDescriptorDefaultName_00653300;

extern "C" const short g_aDiplomacyPlanningQuarterPhaseByNation[7];

extern "C" {
extern TMinor* g_apSecondaryNationStateSlots[36];

#define g_apNationAuxRuntimeStateSlots (g_apSecondaryNationStateSlots + 7)

extern TGreatPower* g_apNationStates[7];
} // extern "C"

extern "C" {

extern "C" float g_afNationOrderQueueDivergence_006a3a88[7];

extern "C" float g_afNationOrderQueueDivergenceMirror_006a3ac0[7];

extern "C" float g_afNationMobileUnitDivergence_006a3ae0[7];

extern "C" float g_afNationWeightedMilitaryOrderScore_006a3b20[7];

extern "C" float g_afNationCombinedUnitDivergence_006a3b50[7];

extern "C" float g_afNationMobileUnitScore_006a3b88[7];

extern float g_DAT_Value_00653308[8];

extern float g_DAT_Value_00653328[6];

extern float g_DAT_Value_00653340[8];

extern float g_DAT_Value_00653360[6];

extern float g_DAT_Value_00653378[8];

extern float g_DAT_Value_00653398[6];

extern float g_DAT_006533b0_Value_006533B0[8];

extern float g_DAT_006533d0_Value_006533D0[6];

extern float g_DAT_006533e8_Value_006533E8[8];

extern float g_DAT_Value_00653408[6];

extern const float g_Compute_Advisory_Handler_LookupTable_00653700; // 0.0f

extern float g_Compute_Advisory_Handler_LookupTable_00653714; // -0.25f

extern float g_Iterate_Linked_List_Value_00653718; // 0.25f

extern float g_Compute_City_Order_Value_0065371C; // 0.5f

extern float g_Compute_Advisory_Handler_LookupTable_00653720; // -90.0f

extern float g_Compute_Advisory_Peer_LookupTable_00653724; // -0.5f

extern float g_afAdvisoryMissionTierThresholdByMinisterSkill_00653F18[5][6];

extern const float g_Compute_Advisory_Zero_00653FD0;

extern float g_Compute_Advisory_Map_Value_00653FD4;

extern double g_Compute_Advisory_MinusSix_00653FE8;

extern double g_Compute_Advisory_MinusHundred_00653FF0;

extern float g_Compute_Advisory_MinusSixFloat_00653FF8;

extern double g_Compute_Advisory_Hundred_00654000;

extern double g_Compute_Advisory_OnePointFive_00654008;

extern float g_Classify_Nation_Military_Value_00653704;

extern float g_Classify_Nation_Military_Value_00653708;

extern float g_Classify_Nation_Military_Value_0065370C;

extern float g_Classify_Nation_Military_Value_00653710;

// Per-order-type sort priority table (slot 0x55 selection sort).
extern short g_DAT_006966d0_Value_006966D0[12];

extern short g_Rebuild_Primary_Nation_Value_00653570[5][0x17];

extern short g_industryActionCostWeightResCode09[16];

extern short g_industryActionCostWeightResCode08[16];

extern short g_industryActionCostWeightResCode0B[16];

extern short g_industryActionCostWeightResCode03[16];

extern short g_industryActionCostWeightResCode0C[16];

extern short g_cachedAiCityActionNationSlot_006967d4;

extern short g_cachedAiCityActionTurnTick_006967d8;

extern float g_cachedAiCityActionContextBias[3];

extern char g_szUCountrySourcePath_00696728[];

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
extern double g_DAT_00653fc0_Value_00653FC0; // 1/255

extern double g_DAT_00653fc8_Value_00653FC8; // 32767.0

extern double g_Evaluate_Advisory_Case11_Value_00653FD8; // 0.5

extern const float g_MissionDefaultScore_006545d0;

extern const double g_AiPressureUnsetSentinel_006545c8;

extern const double g_MissionScoreOneConstant_006545d8;

extern const float g_AiPressureRatioCap_006545e0;

extern const double g_AiPressureMidpointScale_006545e8;

extern const float g_AiPressurePeerScale_006543e8;

extern const double g_MissionScoreZeroThreshold_006545f0;

extern const double g_MissionEligibilityRatioMargin_006545f8;
extern float g_ApplyIndexedResourceDeltaScale_00653728;
extern const float g_MissionDefaultScore_0065a468;
extern const double g_MissionScoreOneConstant_0065a470;
extern const double g_MinisterWeightHalf_006548E8;
extern const double g_MinisterWeightOne_006548F0;
extern const double g_BismarckWeightHigh_006548F8;
extern const double g_BismarckWeightLow_00654900;
extern const float g_DefenderMinisterWeight_00654908;
extern const double g_BullyWeightLow_00654910;
extern const double g_BullyWeightHigh_00654918;

extern short g_industryActionCostWeightResCode10[16];
extern AiCityActionCostProfile g_aiCityActionCostProfiles[30];
extern short g_anProvinceNameOrdinalByNationSlot_006a5af0[23];
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
