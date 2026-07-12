#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TSortedPtrList;
class TView;

// Mac oracle: HelpSetRecord — 0xe bytes stored in TSortedPtrList (recordSize14 0xe).
struct HelpSetRecord {
  short helpSetIdA;
  short helpSetIdB;
  short helpSetIdC;
  short contextId;
  short rank;
  unsigned char flagByte;
  unsigned char padByte;
  short category;
};

ASSERT_SIZE(HelpSetRecord, 0xe);

// TODO(manifest): describe THelpMgr and its role. Base edge (TObject) recovered from RTTI
// CRuntimeClass chain: THelpMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x00657040
class THelpMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (THelpMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(THelpMgr)
  virtual ~THelpMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x500fe0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x500f50
  virtual void Free() override;                    // slot 0x07 0x501070
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined InitializeHelpManagerIndexArrayAndState(); // slot 0x0a 0x500680
  virtual undefined OrphanCallChain_C1_I22_00500f10();         // slot 0x0b 0x500f10
  // === END GENERATED DECLS (THelpMgr) ===

  // Empty release-build hook invoked (this = g_pHelpMgr) after diplomacy policy/grant
  // state changes (callers 0x4dd040/0x4ddfc0/0x4de340 push three args and load ECX from
  // 0x6a21b8). Name is behavioral, kept from the old free-function model.
  void NoOpDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                           int acceptedFlag); // 0x5033e0

  void HandlePostDispatchTurnStateEventUpdates();
  char HandlePendingEventActivationByCode(short eventCode);
  void HandlePostPendingEventActivationNoOp(short eventCode);
  void ActivatePendingEventAndRefreshView(HelpSetRecord* pendingEntry);

  TSortedPtrList* indexList;
  TView* pendingDialogView8;
  TView* pendingDialogViewC;
  int field10;
  int field14;
  short field18;
  int field1a;
  int field1e;
  int field22;
  int field26;
  short field2a;
  int field2c;
  short helpIndexReady;

  THelpMgr();
};
