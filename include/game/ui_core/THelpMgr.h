#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"
#include "game/turn_event_codes.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TPtrList;
class TWindow;
class TCivUnit;

// Mac oracle: HelpSetRecord — 0xe bytes stored in TPtrList (recordSize14 0xe).
struct HelpSetRecord {
  // The decoded Strings.rsrc corpus establishes one shared ID namespace: this is
  // both the STR# group containing the set/topic labels and the base of the
  // consecutive TEXT body resources selected by THelpPicture::ShowTopic.
  short helpResourceBaseId;
  short previousHelpResourceBaseId;
  short nextHelpResourceBaseId;
  short contextId;
  short rank;
  unsigned char flagByte;
  // The retail initializer leaves the natural alignment byte after this field untouched.
  short topicCount;
};

ASSERT_SIZE(HelpSetRecord, 0xe);

// Two adjacent short counters are cleared as one dword by THelpMgr's constructor, then
// incremented independently by the civilian-completion advisor path.
union THelpCompletionCounterPair {
  short values[2];
  int packed;
};

ASSERT_SIZE(THelpCompletionCounterPair, 4);

#pragma pack(push, 2)
// VTABLE: IMPERIALISM 0x00657040
class THelpMgr : public TObject {
public:
  DECLARE_DYNCREATE(THelpMgr)
  virtual ~THelpMgr() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x500fe0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x500f50
  virtual void Free() override;                    // slot 0x07 0x501070
  virtual void IHelpMgr();                         // slot 0x0a 0x500680
  // Clears the per-help-set rank and pending flag at the start of a new game/turn flow.
  virtual void ResetHelpSetRanksAndFlags(); // slot 0x0b 0x500f10

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

  // Tracks the first few completed civilian construction categories and shows the
  // corresponding one-time localized advisor message. 0x005038b0, __thiscall.
  void TryShowCivilianCompletionMilestoneNotification(TCivUnit* civilianOrderEntry);

  // Periodic "another great power is beating you" advisory (turn-tick-indexed metric
  // comparison, string group 0x2753). 0x501be0, __thiscall (`this` unused).
  char ShowPeriodicNationComparisonAdvisoryIfNeeded();
  char HandlePendingEventActivationByCode(TurnEventCodeStorage eventCode);
  void HandlePostPendingEventActivationNoOp(TurnEventCodeStorage eventCode);
  void ActivatePendingEventAndRefreshView(HelpSetRecord* pendingEntry);
  // 0x5010b0 — scans indexList for the pending event matching the active view's
  // currentTurnEventCode and activates one: the lowest-rank unflagged match wins;
  // otherwise a flagged match, else a zero previousHelpResourceBaseId match, is activated.
  void SelectAndActivatePendingEventForCurrentView();
  // 0x503370 -- finds the first indexList record whose contextId is idx + 0x1a0b and
  // activates it. Used by TStatusPicture/TSpecialQuitPicture's shift+'tab1'/'tab2'/'tab3'
  // debug shortcuts.
  void SelectAndActivatePendingEventTypeOffsetFrom1A0B(int idx);
  // 0x503320 -- finds the first indexList record whose contextId is exactly 0x1a0a and
  // activates it. Used by TQueryFloater::DoEvent's 'fore' branch.
  void SelectAndActivatePendingEventType1A0A();
  // Opens/caches the map-context help dialog and asks its 'GOLD' terrain-help pane
  // to rebuild the action menu for the selected nation/tile context. 0x503ac0.
  void EnsureMapActionContextViewAndBuildDefaultTileMenu(int mapContextIndex);

  // 2-byte packed (like TControl's Mac-heritage records): the field suffixes are the real
  // offsets only under pack(2) — field1a is an int AT 0x1a, and helpIndexReady sits at
  // 0x2e (ctor 0x5005f3 writes word [this+0x2e]; read at 0x5bfae6 as the help detail level).
  TPtrList* indexList;
  TWindow* pendingDialogView8;
  TWindow* pendingDialogViewC;
  // Five independent completion counters consumed by
  // TryShowCivilianCompletionMilestoneNotification. Their short widths and offsets are
  // explicit in the increment/compare instructions at 0x005038b0.
  THelpCompletionCounterPair civilianCompletionCounters10;
  THelpCompletionCounterPair civilianCompletionCounters14;
  short civilianCompletionCounter18;
  int field1a;
  int field1e;
  int field22;
  int field26;
  short field2a;
  short field2c;
  // Help/advisor detail level for info texts: 0 minimal, 1 concise verdict, >= 2 detailed
  // numbers ("indexReady" name is historic; hedged).
  short helpIndexReady;

  THelpMgr();

  // Cycles helpIndexReady through 0 -> 1 -> 2 -> 0 (trade-desk info detail level).
  // 0x00503b90, __thiscall.
  void CycleTradeScreenMode0To2();
};
#pragma pack(pop)
ASSERT_SIZE(THelpMgr, 0x30);

// 0x00502b60 (free function in the THelpMgr TU): once per turn tick, show the
// active nation's turn alerts (mission-score comparisons, treasury prompt, commodity
// shortfalls, need overruns, population storms) through
// TViewMgr::ModalMessage; returns nonzero when any alert
// was dispatched.
char ShowTurnAlertsForActiveNation();

#ifdef IMPERIALISM_RUNTIME_TESTS
void ResetCapitolDangerWarningObservationForRuntimeTest();
int CapitolDangerWarningEvaluationCountForRuntimeTest();
bool WasCapitolDangerWarningEvaluatedAtPeaceForRuntimeTest();
int CapitolDangerThreatMaskForRuntimeTest();
int CapitolDangerDisplayedMaskForRuntimeTest();
#endif
