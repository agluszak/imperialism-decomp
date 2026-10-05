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

  void NoOpDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                           int acceptedFlag); // 0x5033e0

  void HandlePostDispatchTurnStateEventUpdates();

  short DispatchTurnStateSpecialAdvisoriesAndReturnCount();

  void ShowPeriodicCapabilityReminderIfNeeded();

  void CheckUnitAdvice(TCivUnit* civilianOrderEntry);

  char ShowPeriodicNationComparisonAdvisoryIfNeeded();
  char HandlePendingEventActivationByCode(TurnEventCodeStorage eventCode);
  void HandlePostPendingEventActivationNoOp(TurnEventCodeStorage eventCode);
  void ShowHelpSet(HelpSetRecord* pendingEntry);
  HelpSetRecord* FindHelpSetRecordByResourceBase(short helpResourceBaseId);
  char GetHelpSetRecordFlagByResourceBase(short helpResourceBaseId);
  char IncrementCivilianCompletionCounterAndCheckThreshold(unsigned int index);
  void SelectAndActivatePendingEventForCurrentView();
  void SelectAndActivatePendingEventTypeOffsetFrom1A0B(int idx);
  void SelectAndActivatePendingEventType1A0A();
  void EnsureMapActionContextViewAndBuildDefaultTileMenu(int mapContextIndex);

  TPtrList* indexList;
  TWindow* pendingDialogView8;
  TWindow* pendingDialogViewC;
  // Five consecutive shorts at +0x10, persisted as one big-endian block.
  short civilianCompletionCounts[5];
  int unusedInitializedState1A;
  int unusedInitializedState1E;
  int unusedInitializedState22;
  int unusedInitializedState26;
  short unusedInitializedState2A;
  unsigned char unusedInitializedState2C;
  // Trade advice detail: 0 minimal, 1 verdict, 2 detailed numbers.
  short tradeAdviceDetailLevel;

  THelpMgr();

  void ToggleTradeAdvice();
};
#pragma pack(pop)
ASSERT_SIZE(THelpMgr, 0x30);
ASSERT_OFFSET(THelpMgr, civilianCompletionCounts, 0x10);
ASSERT_OFFSET(THelpMgr, tradeAdviceDetailLevel, 0x2e);

bool ShowTurnAlertsForActiveNation();

#ifdef IMPERIALISM_RUNTIME_TESTS
void ResetCapitolDangerWarningObservationForRuntimeTest();
int CapitolDangerWarningEvaluationCountForRuntimeTest();
bool WasCapitolDangerWarningEvaluatedAtPeaceForRuntimeTest();
int CapitolDangerThreatMaskForRuntimeTest();
int CapitolDangerDisplayedMaskForRuntimeTest();
void ResetTurnAlertObservationForRuntimeTest();
int TurnAlertObservationCountForRuntimeTest();
short TurnAlertBodyIndexForRuntimeTest(int index);
void SetTurnAlertObservationOnlyForRuntimeTest(bool enabled);
#endif
