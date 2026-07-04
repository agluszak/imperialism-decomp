#pragma once

#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TStream;
class TDealList;

// The nation-interaction / trade-metric manager. Its singleton instance is the global
// g_pNationInteractionStateManager (0x6a43cc), allocated 0xaf0 bytes and constructed via
// the ctor at 0x5b7a20, which installs vtable 0x66d990. Base edge (TObject) recovered from
// the RTTI CRuntimeClass chain (TTradeMgr -> TObject -> CObject).
//
// This was previously conflated with TDealList: the manager's ctor/fields/metric methods
// had been bolted onto `class TDealList : TSortedPtrList` (vtable 0x66da38, size 0x18).
// They are two distinct classes related by COMPOSITION — TTradeMgr::categoryRankLists holds
// TDealList instances (InitializeDefaults installs vtable 0x66da38 into each). The manager
// half has now been detangled out into this class.
// VTABLE: IMPERIALISM 0x0066d990
class TTradeMgr : public TObject {
public:
  DECLARE_DYNCREATE(TTradeMgr)
  virtual ~TTradeMgr(); // slot 0x01 (scalar deleting destructor, 0x5b7a40)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  void WriteTo(TStream* stream) override;  // slot 0x05 0x5b7d90
  void ReadFrom(TStream* stream) override; // slot 0x06 0x5b7c10
  void Free() override;                    // slot 0x07 0x5b7bc0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)

  // Introduced virtuals (slots 0x0a-0x22), declared in slot order so the compiler lays
  // out vtable 0x66d990 correctly. The four with real bodies keep their established
  // (caller-facing) names; the rest are honest stubs pending their own port.
  virtual undefined4 OrphanCallChain_C3_I50_005b7fc0();                           // 0x0a 0x5b7fc0
  virtual undefined4 AccumulateDiplomacyRelationChangesAndQueueEvents();          // 0x0b 0x5b8080
  virtual undefined4 DispatchNationMetricUpdatePassForAllSlots();                 // 0x0c 0x5b8aa0
  virtual undefined4 ComputeNationMetricBaselineValueForSlot();                   // 0x0d 0x5b8ad0
  virtual undefined4 GetNationMetricWeightedScoreForSlot();                       // 0x0e 0x5b8d40
  virtual short IsCapabilityCategoryActiveSlot3C(short category);                 // 0x0f 0x5b8d70
  virtual undefined4 ComputeNationMetricDispatchScoreAndResolveScale();           // 0x10 0x5b8da0
  virtual undefined4 GetNationMetricRosterWordAtOffset0E();                       // 0x11 0x5b8f80
  virtual undefined4 GetNationMetricRosterWordAtOffset0C();                       // 0x12 0x5b8fb0
  virtual short QueryProposalWeightSlot4C(short metricSlot);                      // 0x13 0x5b8fe0
  virtual undefined4 GetNationMetricBucketValueByIndex();                         // 0x14 0x5b9030
  virtual undefined4 ApplyDiplomacyTransferEffectsAcrossNationMetricRoster();     // 0x15 0x5b9060
  virtual undefined4 ProcessPendingDiplomacyTransferEntriesUntilBlockedWrapper(); // 0x16 0x5b9190
  virtual undefined4 RebuildNationMetricPassesAndClampRowsByBaseline();           // 0x17 0x5b9410
  virtual void DispatchProposalAmountSlot60(short ownerNation, int sourceContext, int amount,
                                            int maxAmount, int targetNation, char emitEventFlag,
                                            char skipLocalizationBranch);        // 0x18 0x5b94d0
  virtual undefined4 SetNationMetricCellValueByIndex();                          // 0x19 0x5b9790
  virtual undefined4 RunNationUpdatePassesAndResetTransitionFlags();             // 0x1a 0x5b97c0
  virtual undefined4 RunNationMetricPreUpdatePassAcrossSecondaryNations();       // 0x1b 0x5b9890
  virtual undefined4 BuildSecondaryNationMetricBucketsAndWeightedTrendScores();  // 0x1c 0x5b9b30
  virtual undefined4 BuildEligibleNationMetricBucketsAndWeightedTrendScores();   // 0x1d 0x5b98d0
  virtual undefined4 IsNationMetricCellNegative();                               // 0x1e 0x5b9f70
  virtual undefined4 IsNationMetricCellPositive();                               // 0x1f 0x5b9fa0
  virtual undefined4 AllocateAndPopulateLinkedValueCollectionFromRosterFilter(); // 0x20 0x5b9fd0
  virtual short ResolveProposalCodeForCategorySlot84(int proposalCode,
                                                     int category); // 0x21 0x5ba090
  virtual undefined4 ComputeNationMetricPowerScale();               // 0x22 0x5b9f30

  TTradeMgr();
  void InitializeNationInteractionStateManagerDefaults();

  // One 0xa0-byte metric row per category, indexed from class offset 0x04. Field offsets
  // recovered from the accessors (0x5b8d70/0x5b8fe0): element access resolves to
  // `this + index*0xa0 + 0x{0a,18}`, i.e. array-base 0x04 + struct-offset {0x06,0x14}.
  struct NationMetricCategoryRow {
    unsigned char pad00[0x06];
    short proposalWeightScale06; // struct 0x06 -> this + index*0xa0 + 0x0a
    unsigned char pad08[0x14 - 0x08];
    short capabilityActiveFlag14; // struct 0x14 -> this + index*0xa0 + 0x18
    unsigned char pad16[0xa0 - 0x16];
  };

  NationMetricCategoryRow categoryRows[0x11]; // 0x04 .. 0xaa3
  unsigned char padAA4[0xaa8 - 0xaa4];        // 0xaa4 .. 0xaa7
  TDealList* categoryRankLists[0x11];         // 0xaa8 .. 0xaeb (TDealList: vtable 0x66da38)
  unsigned char padAEC[0xaf0 - 0xaec];        // 0xaec .. 0xaef
};

ASSERT_SIZE(TTradeMgr, 0xaf0);
