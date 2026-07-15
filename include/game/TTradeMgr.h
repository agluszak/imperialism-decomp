#pragma once

#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TStream;
class TDealList;
class TSoundChannelNode;

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
  virtual ~TTradeMgr() override; // slot 0x01 (scalar deleting destructor, 0x5b7a40)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  void WriteTo(TStream* stream) override;  // slot 0x05 0x5b7d90
  void ReadFrom(TStream* stream) override; // slot 0x06 0x5b7c10
  void Free() override;                    // slot 0x07 0x5b7bc0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)

  // Introduced virtuals (slots 0x0a-0x22), declared in slot order so the compiler lays
  // out vtable 0x66d990 correctly. All carry real, ported bodies (dispatches resolved to
  // real virtuals on the recovered receiver classes).
  virtual void OrphanCallChain_C3_I50_005b7fc0();                     // 0x0a 0x5b7fc0
  virtual void AccumulateDiplomacyRelationChangesAndQueueEvents();    // 0x0b 0x5b8080
  virtual void DispatchNationMetricUpdatePassForAllSlots();           // 0x0c 0x5b8aa0
  virtual void ComputeNationMetricBaselineValueForSlot(short slot);   // 0x0d 0x5b8ad0
  virtual double GetNationMetricWeightedScoreForSlot(short category); // 0x0e 0x5b8d40
  virtual short IsCapabilityCategoryActiveSlot3C(short category);     // 0x0f 0x5b8d70
  virtual int ComputeNationMetricDispatchScoreAndResolveScale(short sourceSlot, short targetSlot,
                                                              short scoreA,
                                                              short scoreB);      // 0x10 0x5b8da0
  virtual short GetNationMetricRosterWordAtOffset0E(short category);              // 0x11 0x5b8f80
  virtual short GetNationMetricRosterWordAtOffset0C(short category);              // 0x12 0x5b8fb0
  virtual short QueryProposalWeightSlot4C(short metricSlot);                      // 0x13 0x5b8fe0
  virtual short GetNationMetricBucketValueByIndex(short category);                // 0x14 0x5b9030
  virtual void ApplyDiplomacyTransferEffectsAcrossNationMetricRoster(short slot); // 0x15 0x5b9060
  virtual void ProcessPendingDiplomacyTransferEntriesUntilBlockedWrapper();       // 0x16 0x5b9190
  virtual void RebuildNationMetricPassesAndClampRowsByBaseline();                 // 0x17 0x5b9410
  virtual void DispatchProposalAmountSlot60(short ownerNation, int sourceContext, int amount,
                                            int maxAmount, int targetNation, char emitEventFlag,
                                            char skipLocalizationBranch);    // 0x18 0x5b94d0
  virtual void SetNationMetricCellValueByIndex(short category, short value); // 0x19 0x5b9790
  virtual void RunNationUpdatePassesAndResetTransitionFlags();               // 0x1a 0x5b97c0
  virtual void RunNationMetricPreUpdatePassAcrossSecondaryNations();         // 0x1b 0x5b9890
  virtual void BuildSecondaryNationMetricBucketsAndWeightedTrendScores();    // 0x1c 0x5b9b30
  virtual void BuildEligibleNationMetricBucketsAndWeightedTrendScores();     // 0x1d 0x5b98d0
  virtual char IsNationMetricCellNegative(int row, int col);                 // 0x1e 0x5b9f70
  virtual char IsNationMetricCellPositive(int row, int col);                 // 0x1f 0x5b9fa0
  virtual TSoundChannelNode*
  AllocateAndPopulateLinkedValueCollectionFromRosterFilter(int rosterSlot,
                                                           int filterValue); // 0x20 0x5b9fd0
  virtual short ResolveProposalCodeForCategorySlot84(short proposalCode,
                                                     short category);        // 0x21 0x5ba090
  virtual double ComputeNationMetricPowerScale(double base, short exponent); // 0x22 0x5b9f30

  TTradeMgr();
  void InitializeNationInteractionStateManagerDefaults();
  // Non-virtual impl invoked by the slot-0x16 wrapper.
  void ProcessPendingDiplomacyTransferEntriesUntilBlocked(); // 0x5b91e0
  // Clears every live TGreatPower's diplomacyState1c6 block, clamps each category row's
  // cells18 turn-history cells to the running max seen 23 cells earlier (the scan
  // deliberately runs past cells18's own bounds into the next row -- rows are laid out
  // contiguously in categoryRows, so this is a genuine flat-buffer traversal in the
  // original, not a bug), then either emits turn-event 3 mode 18 for the active nation or
  // (if the game isn't in that mode) posts the turn-flow UI refresh command.
  void RefreshNationStateAndEmitTurnEvent3Mode18(); // 0x5b9370
  // Average, across all 17 category rows, of (proposalWeightScale06 - presetSeed04).
  // Called from the free function BuildInterNationEventSummaryRowsForAdvisorDialog
  // (0x55d200) while building the advisor-dialog inter-nation event summary rows.
  int ComputeAverageProposalWeightDeltaAcrossCategoryRows(); // 0x5ba0e0

  // One 0xa0-byte metric row per category, indexed from class offset 0x04. Field offsets
  // recovered from the accessors' disassembly: `categoryRows[i].field` resolves to
  // `this + i*0xa0 + (0x04 + struct_off)`. Row stride is 0xa0; struct alignment is 2 (the
  // double at 0x0c is stored unaligned, so it is kept as raw bytes to avoid 8-byte packing).
  struct NationMetricCategoryRow {
    // struct 0x00/0x02 -- only observed written by
    // TTradeMgr::RunNationUpdatePassesAndResetTransitionFlags, and only for categoryRows[0]
    // (a literal this+0x04/this+0x06 write, not a per-row loop); every other row leaves this
    // pair untouched. Named rather than left as padding since a concrete writer exists, but
    // the semantic beyond "reset transition flag pair" is unconfirmed.
    short resetTransitionFlagA00;     // struct 0x00
    short resetTransitionFlagB02;     // struct 0x02
    short presetSeed04;               // struct 0x04
    short proposalWeightScale06;      // struct 0x06
    short field08;                    // struct 0x08
    short field0a;                    // struct 0x0a
    unsigned char weightedScore0c[8]; // struct 0x0c (unaligned double)
    short capabilityActiveFlag14;     // struct 0x14
    short field16;                    // struct 0x16
    short cells18[(0xa0 - 0x18) / 2]; // struct 0x18..0x9f (flat cell matrix, stride 0x50 shorts)
  };

  NationMetricCategoryRow categoryRows[0x11]; // 0x04 .. 0xaa3
  unsigned char padAA4[0xaa8 - 0xaa4];        // 0xaa4 .. 0xaa7
  TDealList* categoryRankLists[0x11];         // 0xaa8 .. 0xaeb (TDealList: vtable 0x66da38)
  unsigned char padAEC[0xaf0 - 0xaec];        // 0xaec .. 0xaef
};

ASSERT_SIZE(TTradeMgr, 0xaf0);
