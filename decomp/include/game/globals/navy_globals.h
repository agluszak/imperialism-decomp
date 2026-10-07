#pragma once
#include "game/globals/global_types.h"

// LAYOUT: fourteen per-resource navy-order descriptors, stride 0x24. Columns are read both as
// signed words and as dwords, so they stay one indexed array.
struct TNavyOrderResourceDescriptor {
  enum Column {
    kFirepower = 0,
    kBattleRange = 1,
    kArmor = 2,
    kHullPoints = 3,
    kBattleSpeed = 4,
    kCargoHold = 5,
    kToolbarSlot = 6,
    kSailingSpeed = 7,
    kPriorityTier = 8,
    kColumnCount = 9
  };

  int valueByColumn[kColumnCount];

  __inline int FirepowerDword() const {
    return valueByColumn[kFirepower];
  }
  __inline short Firepower() const {
    return static_cast<short>(valueByColumn[kFirepower]);
  }
  __inline int BattleRangeDword() const {
    return valueByColumn[kBattleRange];
  }
  __inline short BattleRange() const {
    return static_cast<short>(valueByColumn[kBattleRange]);
  }
  __inline short Armor() const {
    return static_cast<short>(valueByColumn[kArmor]);
  }
  __inline short HullPoints() const {
    return static_cast<short>(valueByColumn[kHullPoints]);
  }
  __inline int BattleSpeedDword() const {
    return valueByColumn[kBattleSpeed];
  }
  __inline short BattleSpeed() const {
    return static_cast<short>(valueByColumn[kBattleSpeed]);
  }
  __inline short CargoHold() const {
    return static_cast<short>(valueByColumn[kCargoHold]);
  }
  __inline int ToolbarSlotDword() const {
    return valueByColumn[kToolbarSlot];
  }
  __inline short ToolbarSlot() const {
    return static_cast<short>(valueByColumn[kToolbarSlot]);
  }
  __inline short SailingSpeed() const {
    return static_cast<short>(valueByColumn[kSailingSpeed]);
  }
  __inline short PriorityTier() const {
    return static_cast<short>(valueByColumn[kPriorityTier]);
  }
};
ASSERT_SIZE(TNavyOrderResourceDescriptor, 0x24);

void RecomputeGlobalCapabilityAverages(void);
void FormatCommodityCount(CString* out, short commodityCode, short count);
int GetNavyOrderCategoryBaseline(int category);

extern short g_awMapContextActionLabelTokenByCommand[17];

// Naval combat damage-split and gunnery hit-chance constants.
extern double g_dNavyDamageSplitRatioA;
extern double g_dNavyDamageSplitRatioB;
extern double g_dNavyHitChanceRangeScale;
extern float g_fNavyHitChanceCubeOffset;
extern float g_fNavyHitChanceNumerator;
extern int g_anNavyTacticalMoveCostsByDirection[6];

extern "C" {
extern TNavyMgr* g_pNavyOrderManager;
extern unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24];
extern unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24];
extern bool g_bDrawOceanRouteOverlay;
extern bool g_bTransferOceanViewportToActiveSurface;
extern bool g_bDrawOceanZoneLabels;
extern bool g_bDrawOceanNationLabels;
extern TShip* g_pNavyPrimaryOrderListHead;

extern "C" TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[14];

extern "C" int g_aCategoryMetricBaselineAverage[4];

extern "C" short g_aNavalIntelligenceAccuracyProfiles[6][6];

extern "C" bool g_bPerfectNavalIntelligenceCheat;

extern "C" TAdmiral* g_pNavySecondaryOrderListHead;

extern int g_UnknownMapOrderExecutionGuard;

extern "C" char s_SourcePathUNewspaper[];

extern "C" char s_SourcePathUNavy[];

extern "C" char s_SourcePathUOcean[];

extern short g_Populate_Beachhead_Mission_LookupTable[];
extern const int g_NavyMissionIndustrialCostTrailingLookup[14];

extern const short g_NavyOrderDistributionCategoryWeights[4];

extern short g_NavyResolveOrderRanking[14];

extern short g_NavyMissionOrderRanking[14];

extern short g_NavyPriorityOrderRanking[14];

extern "C" char s_szLineBreak[8];

extern float g_fMissionScoreNormalizationDivisor;
extern float g_fScatteredShipsMissionDefaultScore;

} // extern "C"
