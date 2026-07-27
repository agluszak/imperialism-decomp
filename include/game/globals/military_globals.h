#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/prelude.h"

// Per-subsystem VPoint equivalents passed to the ModalMessage overloads. The Mac
// signatures provide the semantic type; Windows stores them as zero-initialized POINTs.
extern POINT g_ptArmyOrderModalMessage;      // @ 0x6a2318
extern POINT g_ptArmyValidationModalMessage; // @ 0x6a2288

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
extern int g_anFortLevelAttackerPenaltyPercentByLevel[8];

// Per-unit-type blink/boost eligibility flag (0x64c808), indexed by TUnit::orderType; true
// bound unconfirmed beyond the observed ~28 nonzero/zero entries.
extern unsigned char g_abUnitTypeBlinkEligibilityFlag[32];

// Four per-unit-type meter-scoring tables read by
// TArmyStack::AccumulateWeightedMeterAndCountFromEligibleLinkedEntries, all indexed by
// TUnit::orderType; true bounds unconfirmed beyond the observed sampled entries.
extern int g_anWeightClassByOrderType[32]; // 0x64c790

extern short g_anScaledFactorByOrderType[32]; // 0x64c660

extern float g_afPercentEfficiencyByOrderType[32]; // 0x64c6a0

extern int g_anCountWeightByOrderType[32]; // 0x695578

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

extern float g_ArmyMissionCandidateScoreTable_006978f8[];

extern const float g_InvadeMissionSuppressedPriorContributionScale_0065A95C;

extern const double g_Recompute_Nation_Order_LookupTable_0065A9E0;

} // extern "C"
