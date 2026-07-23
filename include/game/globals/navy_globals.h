#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

// Localized-label string-group indices, keyed by GetMapContextActionCode's return value
// (0..0x10 hold real tokens 0x3f0..0x3f8; the table is read by
// ActionCursor, 0x559dd0).
extern short g_awMapContextActionLabelTokenByCommand[17];

extern "C" {

extern "C" TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[14];

// Per-category (0..3) capability metric baseline averages (0x006a3ec8): recomputed at
// runtime by RecomputeGlobalCapabilityAverages and read back as the normalization divisor
// by the navy/map-order per-category scoring helpers.
extern "C" int g_aCategoryMetricBaselineAverage[4];

// Six admiral-skill rows. Columns 0..2 select an estimated ship count and columns
// 3..5 select class accuracy; each triplet is a percentage distribution.
extern "C" short g_aNavalIntelligenceAccuracyProfiles[6][6];

extern "C" unsigned char g_bPerfectNavalIntelligenceCheat;

extern "C" TAdmiral* g_pNavySecondaryOrderListHead;

// Gates the assert-messagebox in TTaskForce::CarryOutOrders' default
// (unhandled ship-order kind) case; not yet recovered beyond that one read site.
extern int g_UnknownMapOrderExecutionGuard_006a3ee0;

extern "C" const char s_SourcePathUNewspaper_00698470[];

extern "C" const char s_SourcePathUNavy_006983C8[];

extern "C" const char s_SourcePathUOcean_006984CC[];

extern short g_Populate_Beachhead_Mission_LookupTable_00697958[];

// TShip.cpp — per-category target-percentage weights (40/30/30/0) used by
// ComputeNavyOrderDistributionScoreForNation's divergence-score formula. Read via
// sign-extend (movsx) in the original despite being small positive values, so the
// storage type must be signed short to match the codegen.
extern const short g_NavyOrderDistributionCategoryWeights_00697978[4];

extern short g_NavyResolveOrderRanking[14];

extern short g_NavyMissionOrderRanking[14];

extern short g_NavyPriorityOrderRanking[14];

extern "C" const char s_szLineBreak_00695880[8];

} // extern "C"
