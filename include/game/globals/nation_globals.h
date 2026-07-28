#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

class TGreatPower;
class TMinor;

TGreatPower* GetNationStateBySlot(short slotId);
short QueryNationMetricBySlot(TGreatPower* nationState, short metricSlot);

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

// 0x6a4280..0x6a4310 — secondary (minor-power) nation rows; TMinor layout
// (military unit list at +0x44 summed by 0x004e0fe0/0x004e1300).
extern "C" {
extern TMinor* g_apSecondaryNationStateSlots[36];

// Original address 0x006a429c is g_apSecondaryNationStateSlots + 7: the 16 minor
// rows are an interior slice, not independent storage.
#define g_apNationAuxRuntimeStateSlots (g_apSecondaryNationStateSlots + 7)

extern TGreatPower* g_apNationStates[7];
// Several retail loops compare their cursor with the immediate one-past address
// 0x006a438c. It is not a separately allocated pointer object.
#define g_apNationStates_End g_apNationStates[7]
} // extern "C"

extern "C" {

// Per-nation (0..6) output caches written by RecomputeNationOrderPriorityMetrics
// (0x53fe30): a queue-demand divergence score (blended from the 4-category
// TShip navy-order contribution percentages, normalized against
// g_Populate_Beachhead_Mission_LookupTable_00697958), a "mobile units"
// divergence/score pair (from militaryUnitList44 entries with a nonzero
// GetCategory, normalized against g_awTacticalCompositionReferenceProfiles_00697870),
// a "combined units" divergence (mobile + static units), and a final
// military-power-weighted order score.
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

// Float constants used by the TGreatPower relative-power-score family
// (vtable slots 0x8e-0x9e, bodies 0x004e07b0..0x004e1c20).
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

// 0x653704-0x653710 — production-tier classification constants (TGreatPower slot
// 0x82, body 0x004e2880): -1.0, 2.0, 1.0, -2.0.
extern float g_Classify_Nation_Military_Value_00653704;

extern float g_Classify_Nation_Military_Value_00653708;

extern float g_Classify_Nation_Military_Value_0065370C;

extern float g_Classify_Nation_Military_Value_00653710;

// Per-order-type sort priority table (slot 0x55 selection sort).
extern short g_DAT_006966d0_Value_006966D0[12];

// Scenario-level relation preset rows (0x17 shorts per row, stride 0x2e), loaded into
// the relation manager's city stock block by TGreatPower slot 0x39 (0x004df810).
extern short g_Rebuild_Primary_Nation_Value_00653570[5][0x17];

extern short g_industryActionCostWeightResCode09[16];

extern short g_industryActionCostWeightResCode08[16];

extern short g_industryActionCostWeightResCode0B[16];

extern short g_industryActionCostWeightResCode03[16];

extern short g_industryActionCostWeightResCode0C[16];

extern short g_cachedAiCityActionNationSlot_006967d4;

extern short g_cachedAiCityActionTurnTick_006967d8;

extern float g_cachedAiCityActionContextBias[3];

// Source-file path string ("D:\\Ambit\\Cross\\UCountry.cpp") passed with a line number to
// the UI invalidation-flag assert helper from TGreatPower nil-pointer assert hooks.
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

// TGreatPower_AssignTrackedEntryActions.cpp — same conceptual constants as the
// 0x65a468/0x65a470 pair above (0.0f mul/div selector, 1.0 "remaining priority" base)
// but distinct address instances read by 0x4eb8b0's inline scoring, plus a third 0.0
// (double) threshold used for the score-positivity checks there.
extern const float g_MissionDefaultScore_006545d0;

extern const double g_AiPressureUnsetSentinel_006545c8;

extern const double g_MissionScoreOneConstant_006545d8;

extern const float g_AiPressureRatioCap_006545e0;

extern const double g_AiPressureMidpointScale_006545e8;

extern const float g_AiPressurePeerScale_006543e8;

extern const double g_MissionScoreZeroThreshold_006545f0;

extern const double g_MissionEligibilityRatioMargin_006545f8;

} // extern "C"
