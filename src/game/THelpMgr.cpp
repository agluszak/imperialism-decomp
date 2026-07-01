#include "game/THelpMgr.h"

#include "game/TSimMgr.h"
#include "game/TGreatPower.h"
#include "game/TSortedPtrList.h"
#include "game/TWindow.h"
#include "game/TViewMgr.h"
#include "game/TDisplayMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/TMilitaryUnitOrderState.h"

extern "C" char DAT_006a43f0;

namespace {

static const HelpSetRecord kHelpSetIndexBootstrapRecords[] = {
    {0x0bc2, 0x0000, 0x0bcc, 0x07dd, 0x0001, 0, 0, 0x0005},
    {0x0bcc, 0x0bc2, 0x0c94, 0x07dd, 0x0002, 0, 0, 0x0005},
    {0x0bd6, 0x0000, 0x0c44, 0x07db, 0x0001, 0, 0, 0x0005},
    {0x0bea, 0x0000, 0x0bf4, 0x07d9, 0x0001, 0, 0, 0x0005},
    {0x0bf4, 0x0bea, 0x0000, 0x07d9, 0x0003, 0, 0, 0x0004},
    {0x0bfe, 0x0000, 0x0c26, 0x07d8, 0x0001, 0, 0, 0x0005},
    {0x0c08, 0x0000, 0x0000, 0x08fc, 0x0001, 0, 0, 0x0004},
    {0x0c12, 0x0000, 0x0c1c, 0x1a0a, 0x0001, 0, 0, 0x0005},
    {0x0c1c, 0x0c12, 0x0cc6, 0x1a0a, 0x0001, 0, 0, 0x0005},
    {0x0c26, 0x0bfe, 0x0000, 0x07d8, 0x0002, 0, 0, 0x0005},
    {0x0c30, 0x0000, 0x0000, 0x2134, 0x0001, 0, 0, 0x0004},
    {0x0c3a, 0x0000, 0x0000, 0x07de, 0x0001, 0, 0, 0x0005},
    {0x0c44, 0x0bd6, 0x0c4e, 0x07db, 0x0002, 0, 0, 0x0005},
    {0x0c4e, 0x0c44, 0x0000, 0x07db, 0x0003, 0, 0, 0x0005},
    {0x0c62, 0x0000, 0x0000, 0x0547, 0x0001, 0, 0, 0x0003},
    {0x0c6c, 0x0000, 0x0000, 0x0ed8, 0x0001, 0, 0, 0x0005},
    {0x0c76, 0x0000, 0x0000, 0x07e0, 0x0001, 0, 0, 0x0005},
    {0x0c8a, 0x0000, 0x0000, 0x2260, 0x0001, 0, 0, 0x0004},
    {0x0c94, 0x0bcc, 0x0c9e, 0x07dd, 0x0003, 0, 0, 0x0005},
    {0x0c9e, 0x0c94, 0x0ca8, 0x07dd, 0x0004, 0, 0, 0x0005},
    {0x0ca8, 0x0c9e, 0x0000, 0x07dd, 0x0005, 0, 0, 0x0005},
    {0x0cb2, 0x0000, 0x0000, 0x1036, 0x0000, 0, 0, 0x0003},
    {0x0cbc, 0x0000, 0x0000, 0x2103, 0x0001, 0, 0, 0x0005},
    {0x0cc6, 0x0c1c, 0x0000, 0x1a0a, 0x0001, 0, 0, 0x0002},
    {0x0cd0, 0x0000, 0x0000, 0x03b8, 0x0001, 0, 0, 0x0005},
    {0x0cda, 0x0000, 0x0000, 0x10cc, 0x0001, 0, 0, 0x0002},
    {0x0cee, 0x0000, 0x0000, 0x1a0b, 0x0001, 0, 0, 0x0001},
    {0x0d0c, 0x0000, 0x0000, 0x1a0c, 0x0001, 0, 0, 0x0001},
    {0x0d16, 0x0000, 0x0000, 0x1a0d, 0x0001, 0, 0, 0x0001},
    {0x0000, 0x0000, 0x0bb9, 0x0000, 0x0000, 0, 0, 0x0003},
};

static const int kHelpSetIndexBootstrapRecordCount =
    sizeof(kHelpSetIndexBootstrapRecords) / sizeof(kHelpSetIndexBootstrapRecords[0]);

}  // namespace

// FUNCTION: IMPERIALISM 0x005005e0
THelpMgr::THelpMgr() : TObject() {
  pendingDialogView8 = 0;
  pendingDialogViewC = 0;
  helpIndexReady = 0;
  field1a = 0;
  field1e = 0;
  field22 = 0;
  field26 = 0;
  field2a = 0;
  field2c = 0;
  field10 = 0;
  field14 = 0;
  field18 = 0;
  indexList = nullptr;
}
// SYNTHETIC: IMPERIALISM 0x00500550
// THelpMgr::CreateObject

IMPLEMENT_DYNCREATE(THelpMgr, TObject)

THelpMgr::~THelpMgr() {}

undefined THelpMgr::OrphanCallChain_C1_I22_00500f10() { return 0; }

void THelpMgr::ReadFrom(TStream* stream) { (void)stream; }

void THelpMgr::WriteTo(TStream* stream) { (void)stream; }

void THelpMgr::Free() {}

// FUNCTION: IMPERIALISM 0x00500680
undefined THelpMgr::InitializeHelpManagerIndexArrayAndState() {
  helpIndexReady = 1;
  TSortedPtrList* list = new TSortedPtrList();
  indexList = list;
  if (list != nullptr) {
    list->relationType = 0xe;
  }
  if (DAT_006a43f0 == 0 && list != nullptr) {
    int entryIndex;
    for (entryIndex = 0; entryIndex < kHelpSetIndexBootstrapRecordCount; entryIndex++) {
      HelpSetRecord record = kHelpSetIndexBootstrapRecords[entryIndex];
      list->AddEntrySlot38(&record);
    }
  }
  return 0;
}

namespace {

short DispatchTurnStateSpecialAdvisoriesAndReturnCount() { return 0; }

void ShowPeriodicCapabilityReminderIfNeeded() {}

char ShowPeriodicNationComparisonAdvisoryIfNeeded() { return 0; }

void ReleasePendingHelpDialogView(TView** dialogView) {
  if (*dialogView != 0) {
    static_cast<TWindow*>(*dialogView)->OrphanCallChain_C2_I10_0048e120();
    *dialogView = 0;
  }
}

int GetSortedPtrListEntryCount(TSortedPtrList* list) {
  return *reinterpret_cast<int*>(reinterpret_cast<char*>(list) + 0x8);
}

short ReadLocalizationFlowMode() {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x8);
}

short ReadLocalizationTurnGateFlag58() {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x58);
}

short ReadLocalizationPendingEventGate5c() {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x5c);
}

} // namespace

extern "C" short g_nTurnFlowNationComparisonAdvisoryTick;

// FUNCTION: IMPERIALISM 0x005011a0
void THelpMgr::HandlePostDispatchTurnStateEventUpdates() {
  const short nationId = g_pUiRuntimeContext->GetActiveNationId();
  const int flowMode = ReadLocalizationFlowMode();
  if (flowMode == 0xf) {
    TGreatPower* nation = g_apNationStates[nationId];
    if (nation != 0) {
      nation->DispatchPendingStatusPrompts();
      nation->BuildGreatPowerTurnMessageSummaryAndDispatch();
    }
    if (ReadLocalizationTurnGateFlag58() != 0) {
      if (DispatchTurnStateSpecialAdvisoriesAndReturnCount() < 2) {
        ShowPeriodicCapabilityReminderIfNeeded();
      }
    }
  } else if (flowMode == 0x6a && ReadLocalizationTurnGateFlag58() != 0) {
    const short currentTurn = g_pLocalizationTable->GetTurnTickSlot3C();
    if (g_nTurnFlowNationComparisonAdvisoryTick < currentTurn) {
      if (ShowPeriodicNationComparisonAdvisoryIfNeeded() != 0) {
        g_nTurnFlowNationComparisonAdvisoryTick = currentTurn;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005031c0
char THelpMgr::HandlePendingEventActivationByCode(short eventCode) {
  char activateCandidate = 0;
  bool nationAlreadyCurrent = false;
  HelpSetRecord* pendingEntry = 0;

  if (eventCode != 0x7dd && eventCode != 0x3b8) {
    ReleasePendingHelpDialogView(&pendingDialogViewC);
  }

  if (ReadLocalizationPendingEventGate5c() == 0) {
    ReleasePendingHelpDialogView(&pendingDialogView8);
  } else {
    if (eventCode != 0x2103 || DAT_006a43f0 == 0) {
      int index = 1;
      while (!nationAlreadyCurrent && activateCandidate == 0) {
        if (indexList == 0 || index > GetSortedPtrListEntryCount(indexList)) {
          break;
        }
        HelpSetRecord* entry =
            static_cast<HelpSetRecord*>(indexList->GetEntrySlot2C(index));
        if (entry->contextId == eventCode) {
          const short activeNation = g_pUiRuntimeContext->GetActiveNationId();
          if (entry->rank == activeNation) {
            nationAlreadyCurrent = true;
          } else if (entry->flagByte == 0) {
            activateCandidate = 1;
            pendingEntry = entry;
          }
        }
        index++;
      }
    }
    if (activateCandidate != 0 && !nationAlreadyCurrent) {
      ActivatePendingEventAndRefreshView(pendingEntry);
      return activateCandidate;
    }
    ReleasePendingHelpDialogView(&pendingDialogView8);
  }
  return activateCandidate;
}

// FUNCTION: IMPERIALISM 0x00503400
void THelpMgr::HandlePostPendingEventActivationNoOp(short eventCode) {
  (void)eventCode;
}

// FUNCTION: IMPERIALISM 0x00503420
void THelpMgr::ActivatePendingEventAndRefreshView(HelpSetRecord* pendingEntry) {
  if (pendingEntry == 0) {
    return;
  }
  pendingEntry->flagByte = 1;
  pendingEntry->rank = g_pUiRuntimeContext->GetActiveNationId();
  // Full dialog refresh path deferred; mark the help-set entry seen/current-nation.
}
