#pragma once

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TIndexAndRankList.h"
#include "game/TSortedPtrList.h"

class CArchive;

// Mac oracle: TDealList (nation interaction / proposal weight manager).
// VTABLE: IMPERIALISM 0x0066da38
class TDealList : public TSortedPtrList {
public:
// === BEGIN GENERATED DECLS (TDealList) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TDealList)
  virtual ~TDealList(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x412bd0)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 EnumerateStateEntriesAndInvokeObjectCallback inherited unchanged (0x5e1f10)
  // slot 0x06 EnumerateStreamEntriesWithDualCallbacksAndTempBuffer inherited unchanged (0x5e1e50)
  // slot 0x07 ClearAndFreeAllPtrListRecords inherited unchanged (0x4880a0)
  // slot 0x08 InvokePtrListResetHook inherited unchanged (0x4880f0)
  // slot 0x09 ResetPtrListAndShrinkCapacity inherited unchanged (0x488110)
  // slot 0x0a OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x488140)
  // slot 0x0b GetPtrListEntryByOneBasedIndex inherited unchanged (0x488160)
  // slot 0x0c RemovePtrListEntryByOneBasedIndexAndFree inherited unchanged (0x488190)
  // slot 0x0d RemoveFirstPtrListEntry inherited unchanged (0x4881d0)
  // slot 0x0e UpsertPtrListRecordByComparator inherited unchanged (0x4881f0)
  // slot 0x0f AppendCopiedRecordToPtrList inherited unchanged (0x4882c0)
  // slot 0x10 InsertCopiedRecordAtFrontOfPtrList inherited unchanged (0x488310)
  virtual int CompareUnsignedIntsAscending(int lhs, int rhs); // slot 0x11 0x5ba260
// === END GENERATED DECLS (TDealList) ===

  struct NationMetricCategoryRow {
    unsigned char pad00[0x0a];
    short proposalWeightScale0a;
    unsigned char pad0c[0x0c];
    short capabilityActiveFlag18;
    unsigned char pad1a[0xa0 - 0x1a];
  };

  TDealList();
  void InitializeNationInteractionStateManagerDefaults();

  short IsCapabilityCategoryActiveSlot3C(int category);
  short QueryProposalWeightSlot4C(int metricSlot);
  void DispatchProposalAmountSlot60(short ownerNation, int sourceContext, int amount,
                                    int maxAmount, int targetNation, char emitEventFlag,
                                    char skipLocalizationBranch);
  short ResolveProposalCodeForCategorySlot84(int proposalCode, int category);

  NationMetricCategoryRow categoryRows[0x11];
  unsigned char padBetweenRowsAndLists[0x3f8];
  TIndexAndRankList* categoryRankLists[0x11];
};

typedef TDealList TNationInteractionStateManager;

extern TDealList* g_pNationInteractionStateManager;

// === BEGIN GENERATED (TDealList) — refreshed by `just gen-class TDealList`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066da38 (18 slots), object size 0x18, base TSortedPtrList
//   slot 0x00  byte 0x00  0x005ba1a0  override  GetTEventHandlerClassNamePointer
//   slot 0x01  byte 0x04  0x005ba1f0  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00412bd0  inherited GetTEventHandlerClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x005e1f10  inherited VTableSlot05
//   slot 0x06  byte 0x18  0x005e1e50  inherited GetTEventHandlerClassNamePointer
//   slot 0x07  byte 0x1c  0x004880a0  inherited VTableSlot07
//   slot 0x08  byte 0x20  0x004880f0  inherited GetTEventHandlerClassNamePointer
//   slot 0x09  byte 0x24  0x00488110  inherited VTableSlot09
//   slot 0x0a  byte 0x28  0x00488140  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0b  byte 0x2c  0x00488160  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0c  byte 0x30  0x00488190  inherited OrphanCallChain_C11_I88_004874b0
//   slot 0x0d  byte 0x34  0x004881d0  inherited GetTEventHandlerClassNamePointer
//   slot 0x0e  byte 0x38  0x004881f0  inherited SetForeignMinisterReadyFlag14
//   slot 0x0f  byte 0x3c  0x004882c0  inherited ReleaseRuntimeSelectionOwnerAndDestroyObject
//   slot 0x10  byte 0x40  0x00488310  inherited UpdateControlCachedIntFromWindowText
//   slot 0x11  byte 0x44  0x005ba260  override  OrphanRetStub_0059add0
// object size 0x18 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TDealList) ===
