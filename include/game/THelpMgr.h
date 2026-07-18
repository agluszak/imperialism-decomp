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

// VTABLE: IMPERIALISM 0x00657040
class THelpMgr : public TObject {
public:
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

  // Empty release-build hook invoked (this = g_pHelpMgr) after diplomacy policy/grant
  // state changes (callers 0x4dd040/0x4ddfc0/0x4de340 push three args and load ECX from
  // 0x6a21b8). Name is behavioral, kept from the old free-function model.
  void NoOpDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                           int acceptedFlag); // 0x5033e0

  void HandlePostDispatchTurnStateEventUpdates();

  // Walks the active nation's turnEventQueue and poses one localized advisory per
  // qualifying event (codes 0x131/0x13a/0x13b), then the map-context / town-list
  // message summaries and the city production reminder; returns how many advisories
  // were posed. 0x501270, __thiscall (`this` unused).
  short DispatchTurnStateSpecialAdvisoriesAndReturnCount();

  // On turn ticks ending in 0/5, poses the "research a capability" reminder when the
  // active nation has no progress on the current marker tech. 0x501a20, __thiscall
  // (`this` unused).
  void ShowPeriodicCapabilityReminderIfNeeded();

  // Periodic "another great power is beating you" advisory (turn-tick-indexed metric
  // comparison, string group 0x2753). 0x501be0, __thiscall (`this` unused).
  char ShowPeriodicNationComparisonAdvisoryIfNeeded();
  char HandlePendingEventActivationByCode(short eventCode);
  void HandlePostPendingEventActivationNoOp(short eventCode);
  void ActivatePendingEventAndRefreshView(HelpSetRecord* pendingEntry);
  // 0x5010b0 — scans indexList for the pending event matching the active view's
  // currentTurnEventCode and activates one: the lowest-rank unflagged match wins;
  // otherwise a flagged match, else a zero-helpSetIdB match, is activated.
  void SelectAndActivatePendingEventForCurrentView();

  // 2-byte packed (like TControl's Mac-heritage records): the field suffixes are the real
  // offsets only under pack(2) — field1a is an int AT 0x1a, and helpIndexReady sits at
  // 0x2e (ctor 0x5005f3 writes word [this+0x2e]; read at 0x5bfae6 as the help detail level).
#pragma pack(push, 2)
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
  short field2c;
  // Help/advisor detail level for info texts: 0 minimal, 1 concise verdict, >= 2 detailed
  // numbers ("indexReady" name is historic; hedged).
  short helpIndexReady;
#pragma pack(pop)

  THelpMgr();
};

// 0x00502b60 (free function in the THelpMgr TU): once per turn tick, show the
// active nation's turn alerts (mission-score comparisons, treasury prompt, commodity
// shortfalls, need overruns, population storms) through
// TViewMgr::DispatchLocalizedUiMessageWithTemplate; returns nonzero when any alert
// was dispatched.
char ShowTurnAlertsForActiveNation();
