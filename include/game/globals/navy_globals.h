#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

// LAYOUT: fourteen per-resource descriptors at 0x00698108 with stride 0x24.
struct TNavyOrderResourceDescriptor {
  union {
    struct {
      union {
        int resolveWeightDword;
        struct {
          short resolveWeight;
          short resolveWeightHighWord;
        };
      };
      union {
        int calculateWeightDword;
        struct {
          short calculateWeight;
          short calculateWeightHighWord;
        };
      };
      short taskForceWeight;
      short pad0a;
      short stockCap;
      short pad0e;
      int navyPriorityWeight;
      short resourceDescriptorWeightWord0;
      short pad16;
      int enabledFlagOrBucketOffset;
      short descriptorWeight;
      short pad1e;
      short priorityTier;
      short pad22;
    };
    int statColumnDwords[9];
  };
};
ASSERT_SIZE(TNavyOrderResourceDescriptor, 0x24);

void RecomputeGlobalCapabilityAverages(void);
short GetResourceTypeRandomDrawBlockFlag(short resourceType);
short GetResourceDescriptorWord0CByType(short resourceType);
short GetResourceDescriptorWord10ByType(short resourceType);
short GetResourceDescriptorWord14ByType(short resourceType);
short GetResourceDescriptorWord18ByType(short resourceType);
short GetResourceDescriptorWeightWord1ByType(short resourceType);
short GetResourceDescriptorWord20ByType(short resourceType);
short GetResourceDescriptorStatByColumn(short resourceType, short statColumn);
void FormatLocalizedCommodityCountLabelByIndex(CString* out, unsigned int commodityCode,
                                               short count);
int GetNavyOrderCategoryBaseline(int category);

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
