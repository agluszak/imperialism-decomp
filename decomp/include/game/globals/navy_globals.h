#pragma once
#include "game/globals/global_types.h"

// LAYOUT: fourteen per-resource navy-order descriptors at 0x00698108 with stride 0x24.
// The shipyard indexes all nine dword columns dynamically. Gameplay readers give the low
// signed word of each column its domain meaning; the ranking code reads columns 0, 1, and 4
// as full dwords. Keep one physical array model rather than overlapping named and indexed views.
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
void FormatLocalizedCommodityCountLabelByIndex(CString* out, unsigned int commodityCode,
                                               short count);
int GetNavyOrderCategoryBaseline(int category);

extern short g_awMapContextActionLabelTokenByCommand[17];

// Naval combat damage-split and gunnery hit-chance constants.
extern double g_dNavyDamageSplitRatioA_00669f10;
extern double g_dNavyDamageSplitRatioB_00669f18;
extern double g_dNavyHitChanceRangeScale_00669ef8;
extern float g_fNavyHitChanceCubeOffset_00669f00;
extern float g_fNavyHitChanceNumerator_00669f04;
extern int g_anNavyTacticalMoveCostsByDirection[6];

extern "C" {
extern TNavyMgr* g_pNavyOrderManager;
extern unsigned char g_aOceanMapOwnerPaletteIndexByNationTag[24];
extern unsigned char g_aOceanMapBorderPaletteIndexByNationTag[24];
extern const bool g_bDrawOceanRouteOverlay;
extern const bool g_bTransferOceanViewportToActiveSurface;
extern const bool g_bDrawOceanZoneLabels;
extern const bool g_bDrawOceanNationLabels;
extern TShip* g_pNavyPrimaryOrderListHead;

extern "C" TNavyOrderResourceDescriptor g_NavyOrderResourceDescriptorTable[14];

extern "C" int g_aCategoryMetricBaselineAverage[4];

extern "C" short g_aNavalIntelligenceAccuracyProfiles[6][6];

extern "C" bool g_bPerfectNavalIntelligenceCheat;

extern "C" TAdmiral* g_pNavySecondaryOrderListHead;

extern int g_UnknownMapOrderExecutionGuard_006a3ee0;

extern "C" const char s_SourcePathUNewspaper_00698470[];

extern "C" const char s_SourcePathUNavy_006983C8[];

extern "C" const char s_SourcePathUOcean_006984CC[];

extern short g_Populate_Beachhead_Mission_LookupTable_00697958[];
extern const int g_NavyMissionIndustrialCostTrailingLookup_0065A920[14];

extern const short g_NavyOrderDistributionCategoryWeights_00697978[4];

extern short g_NavyResolveOrderRanking[14];

extern short g_NavyMissionOrderRanking[14];

extern short g_NavyPriorityOrderRanking[14];

extern "C" const char s_szLineBreak_00695880[8];

extern float g_fMissionScoreNormalizationDivisor;
extern float g_fScatteredShipsMissionDefaultScore;

} // extern "C"
