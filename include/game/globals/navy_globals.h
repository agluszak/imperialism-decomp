#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

// LAYOUT: fourteen per-resource navy-order descriptors at 0x00698108 with stride 0x24.
// The shipyard indexes all nine dword columns dynamically. Gameplay readers give the low
// signed word of each column its domain meaning; the ranking code reads columns 0, 1, and 4
// as full dwords. Keep one physical array model rather than overlapping named and indexed views.
struct TNavyOrderResourceDescriptor {
  enum Column {
    kResolveWeight = 0,
    kCalculateWeight = 1,
    kTaskForceWeight = 2,
    kStockCap = 3,
    kNavyPriorityWeight = 4,
    kResourceDescriptorWeightWord0 = 5,
    kToolbarBucketIndex = 6,
    kDescriptorWeight = 7,
    kPriorityTier = 8,
    kColumnCount = 9
  };

  int valueByColumn[kColumnCount];

  __inline int ResolveWeightDword() const {
    return valueByColumn[kResolveWeight];
  }
  __inline short ResolveWeight() const {
    return static_cast<short>(valueByColumn[kResolveWeight]);
  }
  __inline int CalculateWeightDword() const {
    return valueByColumn[kCalculateWeight];
  }
  __inline short CalculateWeight() const {
    return static_cast<short>(valueByColumn[kCalculateWeight]);
  }
  __inline short TaskForceWeight() const {
    return static_cast<short>(valueByColumn[kTaskForceWeight]);
  }
  __inline short StockCap() const {
    return static_cast<short>(valueByColumn[kStockCap]);
  }
  __inline int NavyPriorityWeightDword() const {
    return valueByColumn[kNavyPriorityWeight];
  }
  __inline short NavyPriorityWeight() const {
    return static_cast<short>(valueByColumn[kNavyPriorityWeight]);
  }
  __inline short ResourceDescriptorWeightWord0() const {
    return static_cast<short>(valueByColumn[kResourceDescriptorWeightWord0]);
  }
  __inline int ToolbarBucketIndexDword() const {
    return valueByColumn[kToolbarBucketIndex];
  }
  __inline short ToolbarBucketIndex() const {
    return static_cast<short>(valueByColumn[kToolbarBucketIndex]);
  }
  __inline short DescriptorWeight() const {
    return static_cast<short>(valueByColumn[kDescriptorWeight]);
  }
  __inline short PriorityTier() const {
    return static_cast<short>(valueByColumn[kPriorityTier]);
  }
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

// Naval combat damage-split and gunnery hit-chance constants.
extern double g_dNavyDamageSplitRatioA_00669f10;
extern double g_dNavyDamageSplitRatioB_00669f18;
extern double g_dNavyHitChanceRangeScale_00669ef8;
extern float g_fNavyHitChanceCubeOffset_00669f00;
extern float g_fNavyHitChanceNumerator_00669f04;

extern "C" {
extern TNavyMgr* g_pNavyOrderManager;
extern unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24];
extern unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24];
extern const unsigned char g_bDrawOceanRouteOverlay;
extern const unsigned char g_bTransferOceanViewportToActiveSurface;
extern const unsigned char g_bDrawOceanZoneLabels;
extern const unsigned char g_bDrawOceanNationLabels;
extern TShip* g_pNavyPrimaryOrderListHead;

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

extern float g_fMissionScoreNormalizationDivisor;
extern float g_fScatteredShipsMissionDefaultScore;

} // extern "C"
