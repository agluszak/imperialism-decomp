#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern "C" TArmyMgr* g_pMapContextActionManager;
#include "game/globals/tactical_ui_globals.h"

struct MappedFlavorTextNationVariantEntry {
  short variantIndex;
  short pad;
};

// Per-subsystem VPoint equivalents passed to the ModalMessage overloads. The Mac
// signatures provide the semantic type; Windows stores them as zero-initialized POINTs.
extern POINT g_ptArmyOrderModalMessage;      // @ 0x6a2318
extern POINT g_ptArmyValidationModalMessage; // @ 0x6a2288

extern short g_aUnitOrderCostProfileByAbilityId[0x1e][7];

extern short g_MapOrderResourceRollWeightTable_0064c5d8[6][6];

extern "C" {

// Per-unit-type military stat records (7 shorts per type, record base 0x695cd2):
// column 0 = category flag (0x10 = counted toward power/cost), column 1 = power/cost
// points. See TMilitaryUnit::GetArmsCarried (0x5c3400).

// Per-unit-type stat table (7 shorts per type; unit types 0x00-0x1d) and per-stat
// divisor baseline used by TMilitaryUnit::GetAttribute (0x5c3530).
extern "C" short g_UnitTypeStatTable_0066EB88[30][7];

extern "C" short g_UnitTypeStatDivisorTable_0066ED30[7];

// Cursor resource ids keyed by the military/civilian map state classifiers (12 entries each).
extern short g_mapCursorTokenByStateIndex_00695668[12];

extern short g_civilianMapCursorTokenByStateIndex_00695680[12];

// Stack composition class lookup (0x6953c0), indexed [minClass + maxClass*4]; true
// bound unconfirmed beyond the observed min/max class range (1..5-ish).
extern unsigned char g_abStackCompositionClassTable[16];

// Per-fort-level attacker penalty percent (0x695568), indexed by
// Province::fortLevel03; observed values 100/85/75/65/0/0/0/0 for levels
// 0-7 (only the low byte of each int is ever read). Used by
// TArmyMgr::UpdateDualLinkedEntryMetersAndBlinkState to gate the per-unit meter snapshot.
extern int g_anFortLevelAttackerPenaltyPercentByLevel[4];

// Per-unit-type blink/boost eligibility flag (0x64c808), indexed by TUnit::orderType; true
// bound unconfirmed beyond the observed ~28 nonzero/zero entries.
extern unsigned char g_abUnitTypeBlinkEligibilityFlag[30];

// Four per-unit-type meter-scoring tables read by
// TArmyStack::AccumulateWeightedMeterAndCountFromEligibleLinkedEntries, all indexed by
// TUnit::orderType; true bounds unconfirmed beyond the observed sampled entries.
extern int g_anWeightClassByOrderType[30]; // 0x64c790

extern short g_anScaledFactorByOrderType[30]; // 0x64c660

extern float g_afPercentEfficiencyByOrderType[30];    // 0x64c6a0
extern float g_afRandomizedMeterDecayByOrderType[30]; // 0x64c718

extern int g_anCountWeightByOrderType[30]; // 0x695578

// Two 0x20-byte flag tables installed into TArmyMgr+0x14/+0x18 by
// IArmyMgr (0x4a18f0); 8 rows x 4 flag bytes.
extern const signed char g_MapContextStaticTable_00695448[0x20];

extern const unsigned char g_MapContextStaticTable_00695428[0x20];

extern char* g_pMiniCivSharedText_0064cb18;

// Assert source-path string for the UArmyMgr TU.
extern "C" const char s_SourcePathUArmyMgr_0069573C[];

extern "C" const char s_SourcePathUArmyViews_00695858[];

// TArmyMission.cpp / TNavyMission.cpp — shared per-hop/per-province distance decay
// weights (1.0, 0.8, ...), used by both army and navy mission scoring.
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
extern const float g_BlockadePortMissionThreatScale_0065A904;
extern const float g_MissionEmptyResourceWeight_0065AA24;
extern const double g_BeachheadMissionPriorityNormalization_0065AA30;

} // extern "C"
