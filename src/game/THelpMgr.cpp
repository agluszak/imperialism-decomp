#include "game/THelpMgr.h"

#include "game/TSimMgr.h"
#include "game/TGreatPower.h"
#include "game/TSortedPtrList.h"
#include "game/TCity.h"
#include "game/TPopulationMgr.h"
#include "game/TDiplomacyMgr.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TWindow.h"
#include "game/TViewMgr.h"
#include "game/TDisplayMgr.h"
#include "game/global_data_tables.h"
#include "game/turn_flow_cooldown.h"
#include "game/ui_invalidation_guard.h"
#include "game/TMilitaryUnit.h"
#include "game/TTechMgr.h"
#include "game/mapped_flavor_text.h"
#include "game/nation_slot_eligibility.h"

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

} // namespace
// SYNTHETIC: IMPERIALISM 0x00500550
// THelpMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x005005c0
// THelpMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(THelpMgr, TObject)

THelpMgr::~THelpMgr() {}

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

// SYNTHETIC: IMPERIALISM 0x00500630
// THelpMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00500680
undefined THelpMgr::InitializeHelpManagerIndexArrayAndState() {
  helpIndexReady = 1;
  TSortedPtrList* list = new TSortedPtrList();
  indexList = list;
  if (list != nullptr) {
    list->recordSize14 = 0xe;
  }
  if (g_bMultiplayerScenarioSetupActive == 0 && list != nullptr) {
    int entryIndex;
    for (entryIndex = 0; entryIndex < kHelpSetIndexBootstrapRecordCount; entryIndex++) {
      HelpSetRecord record = kHelpSetIndexBootstrapRecords[entryIndex];
      list->InsertCopiedRecordSortedByComparator(&record);
    }
  }
  return 0;
}

namespace {

void ReleasePendingHelpDialogView(TView** dialogView) {
  if (*dialogView != 0) {
    static_cast<TWindow*>(*dialogView)->CloseAndFree();
    *dialogView = 0;
  }
}

int GetSortedPtrListEntryCount(TSortedPtrList* list) {
  // +0x8 is CPtrArray::m_nSize; GetSize() reads exactly that.
  return list->GetSize();
}

__inline int ReadLocalizationFlowMode() {
  return g_pSimMgr->mode;
}

__inline short ReadLocalizationTurnGateFlag58() {
  return g_pSimMgr->preferenceValues[8];
}

__inline short ReadLocalizationPendingEventGate5c() {
  return g_pSimMgr->preferenceValues[10];
}

} // namespace

// FUNCTION: IMPERIALISM 0x00500f10
undefined THelpMgr::OrphanCallChain_C1_I22_00500f10() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00500f50
void THelpMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00500fe0
void THelpMgr::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00501070
void THelpMgr::Free() {}

// FUNCTION: IMPERIALISM 0x005010b0
void THelpMgr::SelectAndActivatePendingEventForCurrentView() {
  HelpSetRecord* best = nullptr;             // lowest-rank unflagged match
  HelpSetRecord* flaggedCandidate = nullptr; // context match with flagByte set
  HelpSetRecord* zeroIdCandidate = nullptr;  // context match, rank>=threshold, helpSetIdB==0
  short threshold = g_pSimMgr->GetTurnTickSlot3C();
  short contextId = g_pUiRuntimeContext->currentTurnEventCode;
  for (int index = 1; index <= GetSortedPtrListEntryCount(indexList); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->contextId == contextId) {
      if (record->flagByte != 0) {
        flaggedCandidate = record;
      } else if (record->rank >= threshold) {
        if (record->helpSetIdB == 0) {
          zeroIdCandidate = record;
        }
      } else {
        best = record;
        threshold = record->rank;
      }
    }
  }
  if (best != nullptr) {
    ActivatePendingEventAndRefreshView(best);
    return;
  }
  HelpSetRecord* fallback = flaggedCandidate;
  if (fallback == nullptr) {
    fallback = zeroIdCandidate;
  }
  if (fallback != nullptr) {
    ActivatePendingEventAndRefreshView(fallback);
  }
}

// FUNCTION: IMPERIALISM 0x005011a0
void THelpMgr::HandlePostDispatchTurnStateEventUpdates() {
  const short nationId = g_pSimMgr->GetActiveNationId();
  const int flowMode = ReadLocalizationFlowMode();
  if (flowMode != 0xf) {
    if (flowMode == 0x6a && ReadLocalizationTurnGateFlag58() != 0) {
      if (g_nTurnFlowNationComparisonAdvisoryTick < g_pSimMgr->GetTurnTickSlot3C()) {
        if (ShowPeriodicNationComparisonAdvisoryIfNeeded() != 0) {
          g_nTurnFlowNationComparisonAdvisoryTick = g_pSimMgr->GetTurnTickSlot3C();
        }
      }
    }
    return;
  }
  // No null check in the original: the 0xf flow mode guarantees the active nation slot.
  g_apNationStates[nationId]->DispatchPendingStatusPrompts();
  g_apNationStates[nationId]->BuildGreatPowerTurnMessageSummaryAndDispatch();
  if (ReadLocalizationTurnGateFlag58() != 0) {
    if (DispatchTurnStateSpecialAdvisoriesAndReturnCount() < 2) {
      ShowPeriodicCapabilityReminderIfNeeded();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00501270
short THelpMgr::DispatchTurnStateSpecialAdvisoriesAndReturnCount() {
  g_pSimMgr->GetTurnTickSlot3C();
  short activeNation = g_pSimMgr->GetActiveNationId();
  CString titleText;
  CString templateText;
  CString nationNameText;
  CString formattedText;
  int activeNationIndex = activeNation;
  TCity* activeCity;
  if (g_apNationStates[activeNationIndex] != 0) {
    activeCity = g_apNationStates[activeNationIndex]->city;
  } else {
    activeCity = 0;
  }
  CString minorNameText;
  short advisoryCount = 0;
  TSortedByRelationshipList* queue = g_apNationStates[activeNationIndex]->turnEventQueue;
  int i;
  for (i = 1; i <= queue->GetSize(); ++i) {
    short* eventRecord = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(i));
    switch (eventRecord[0]) {
    case 0x13b: {
      short standingNation = static_cast<short>(
          g_pDiplomacyTurnStateManager->IsNationSlotEligibleForEventProcessing(eventRecord[1]));
      if (standingNation != activeNation) {
        g_apNationStates[standingNation]->FormatOverlayTerrainLabelText(&nationNameText);
        g_apSecondaryNationStateSlots[eventRecord[1]]->FormatOverlayTerrainLabelText(
            &minorNameText);
        g_pSimMgr->GetString(0x2753, 0x1e, &titleText);
        g_pSimMgr->GetString(0x2753, 0x1f, &templateText);
        scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationNameText),
                               static_cast<LPCSTR>(minorNameText));
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            3, titleText, formattedText, &g_cstrNationComparisonMessageStore, 0, 0);
        ++advisoryCount;
      }
      break;
    }
    case 0x13a: {
      short standingNation = static_cast<short>(
          g_pDiplomacyTurnStateManager->SelectNationSlotFromCollectedStandingEntriesSlot98(
              eventRecord[1], 1));
      if (standingNation != activeNation) {
        g_apNationStates[standingNation]->FormatOverlayTerrainLabelText(&nationNameText);
        g_apSecondaryNationStateSlots[eventRecord[1]]->FormatOverlayTerrainLabelText(
            &minorNameText);
        g_pSimMgr->GetString(0x2753, 0x1a, &titleText);
        g_pSimMgr->GetString(0x2753, 0x1b, &templateText);
        scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(minorNameText),
                               static_cast<LPCSTR>(nationNameText));
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            3, titleText, formattedText, &g_cstrNationComparisonMessageStore, 0, 0);
        ++advisoryCount;
      }
      break;
    }
    case 0x131: {
      g_apNationStates[eventRecord[1]]->FormatOverlayTerrainLabelText(&nationNameText);
      g_pSimMgr->GetString(0x2753, 0x1c, &titleText);
      g_pSimMgr->GetString(0x2753, 0x1d, &templateText);
      scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(nationNameText));
      g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
          3, titleText, formattedText, &g_cstrNationComparisonMessageStore, 0, 0);
      ++advisoryCount;
      break;
    }
    }
  }

  CString contextMessageText(g_pszEmptyTextPointer_00656f60);
  if (g_apNationStates[activeNationIndex]->BuildGreatPowerMapContextTriggeredNationEventMessages(
          &contextMessageText) != 0) {
    g_pSimMgr->GetString(0x2753, 0x3c, &titleText);
    g_pSimMgr->GetString(0x2753, 0x3d, &templateText);
    CString combinedText = templateText + contextMessageText;
    formattedText = combinedText;
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        3, titleText, formattedText, &g_cstrNationComparisonMessageStore, 1, 0);
  }

  contextMessageText = CString(g_pszEmptyTextPointer_00656f60);
  if (g_apNationStates[activeNationIndex]->BuildGreatPowerEligibleNationEventMessagesFromLinkedList(
          &contextMessageText) != 0) {
    g_pSimMgr->GetString(0x2753, 0x42, &titleText);
    g_pSimMgr->GetString(0x2753, 0x43, &templateText);
    templateText += contextMessageText;
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        3, titleText, templateText, &g_cstrNationComparisonMessageStore, 1, 0);
  }

  if (activeCity != 0 && activeCity->field06 != 0 && activeCity->field08 == 0) {
    g_pSimMgr->GetString(0x2753, 0x16, &titleText);
    g_pSimMgr->GetString(0x2753, 0x17, &templateText);
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, titleText, templateText, &g_cstrNationComparisonMessageStore, 2, 0);
    ++advisoryCount;
  }
  return advisoryCount;
}

// FUNCTION: IMPERIALISM 0x00501a20
void THelpMgr::ShowPeriodicCapabilityReminderIfNeeded() {
  short tickMod = static_cast<short>(g_pSimMgr->GetTurnTickSlot3C() % 10);
  short activeNation = g_pSimMgr->GetActiveNationId();
  CString titleText;
  CString messageText;
  // Constructed and destroyed unused in the original (EH state 2).
  CString unusedText;
  if (tickMod == 0 || tickMod == 5) {
    if (g_pCityOrderCapabilityState->orderCapRows277[activeNation]
            .techStatusByTechId[g_pCityOrderCapabilityState->marker262] == 0) {
      g_pSimMgr->GetString(0x2753, 0x18, &titleText);
      g_pSimMgr->GetString(0x2753, 0x19, &messageText);
      g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
          5, titleText, messageText, &g_cstrNationComparisonMessageStore, 2, 0);
    }
  }
}

// Periodic "another great power is beating you" advisory: every turn tick maps to one of
// ten comparison metrics; when some eligible nation's metric exceeds twice the active
// nation's, a localized advisory (string group 0x2753) is formatted and dispatched.
// FUNCTION: IMPERIALISM 0x00501be0
char THelpMgr::ShowPeriodicNationComparisonAdvisoryIfNeeded() {
  short activeNation = g_pSimMgr->GetActiveNationId();
  CString formatText;
  CString templateText;
  CString nationName;
  CString message;
  char advisoryShown = 0;

  switch (static_cast<short>(g_pSimMgr->GetTurnTickSlot3C() % 10)) {
  case 0: {
    TGreatPower* active = g_apNationStates[activeNation];
    short best = (active != 0) ? active->needCapA6 : 0;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0) {
        TGreatPower* nation = g_apNationStates[i];
        short value = (nation != 0) ? nation->needCapA6 : 0;
        if (value > best) {
          best = (nation != 0) ? nation->needCapA6 : 0;
          bestNation = i;
        }
      }
    }
    TGreatPower* mine = g_apNationStates[activeNation];
    short mineValue = (mine != 0) ? mine->needCapA6 : 0;
    if (best <= mineValue * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 0, &formatText);
    g_pSimMgr->GetString(0x2753, 1, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
    advisoryShown = 1;
  } break;

  case 3: {
    short best = g_apNationStates[activeNation]->tradeCapacity;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->tradeCapacity > best) {
        best = g_apNationStates[i]->tradeCapacity;
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->tradeCapacity * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 2, &formatText);
    g_pSimMgr->GetString(0x2753, 3, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 0, 0);
    advisoryShown = 1;
  } break;

  case 6: {
    short best = g_apNationStates[activeNation]->ComputeNationRuntimeAdvisoryMetricCase6();
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->ComputeNationRuntimeAdvisoryMetricCase6() > best) {
        best = g_apNationStates[i]->ComputeNationRuntimeAdvisoryMetricCase6();
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->ComputeNationRuntimeAdvisoryMetricCase6() * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 4, &formatText);
    g_pSimMgr->GetString(0x2753, 5, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
    advisoryShown = 1;
  } break;

  case 2: {
    int best = g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(0);
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->GetCityBuildingProductionSlot8D(0) > best) {
        best = g_apNationStates[i]->GetCityBuildingProductionSlot8D(0);
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(0) * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 6, &formatText);
    g_pSimMgr->GetString(0x2753, 7, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
    advisoryShown = 1;
  } break;

  case 5: {
    int best = g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(2);
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->GetCityBuildingProductionSlot8D(2) > best) {
        best = g_apNationStates[i]->GetCityBuildingProductionSlot8D(2);
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(2) * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 8, &formatText);
    g_pSimMgr->GetString(0x2753, 9, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
    advisoryShown = 1;
  } break;

  case 7: {
    int best = g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(4);
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->GetCityBuildingProductionSlot8D(4) > best) {
        best = g_apNationStates[i]->GetCityBuildingProductionSlot8D(4);
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(4) * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 0xa, &formatText);
    g_pSimMgr->GetString(0x2753, 0xb, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
    advisoryShown = 1;
  } break;

  case 8: {
    if (g_pCityOrderCapabilityState->hasProductionOrder193 == 0) {
      break;
    }
    if (g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(6) == 0) {
      int best = 0;
      short bestNation = activeNation;
      for (short i = 0; i < 7; ++i) {
        if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
            g_apNationStates[i]->GetCityBuildingProductionSlot8D(6) > best) {
          best = g_apNationStates[i]->GetCityBuildingProductionSlot8D(6);
          bestNation = i;
        }
      }
      if (best <= 4) {
        break;
      }
      if (g_pCityOrderCapabilityState->orderCapRows277[activeNation].techStatusByTechId[0x13] !=
          0) {
        g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
        g_pSimMgr->GetString(0x2753, 0xc, &formatText);
        g_pSimMgr->GetString(0x2753, 0xd, &templateText);
        scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationName));
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
        advisoryShown = 1;
      } else {
        g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
        g_pSimMgr->GetString(0x2753, 0xe, &formatText);
        g_pSimMgr->GetString(0x2753, 0xf, &templateText);
        scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationName));
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
        advisoryShown = 1;
      }
    } else {
      int best = g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(6);
      short bestNation = activeNation;
      for (short i = 0; i < 7; ++i) {
        if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
            g_apNationStates[i]->GetCityBuildingProductionSlot8D(6) > best) {
          best = g_apNationStates[i]->GetCityBuildingProductionSlot8D(6);
          bestNation = i;
        }
      }
      if (best <= g_apNationStates[activeNation]->GetCityBuildingProductionSlot8D(6) * 2) {
        break;
      }
      g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
      g_pSimMgr->GetString(0x2753, 0x10, &formatText);
      g_pSimMgr->GetString(0x2753, 0x11, &templateText);
      scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(nationName));
      g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
          5, formatText, message, &g_cstrNationComparisonMessageStore, 2, 0);
      advisoryShown = 1;
    }
  } break;

  case 1: {
    int firstValue = g_apNationStates[activeNation]->ComputeSelectedMilitaryPowerScore();
    int best = firstValue;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (i != activeNation && g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->ComputeSelectedMilitaryPowerScore() > best) {
        best = g_apNationStates[i]->ComputeSelectedMilitaryPowerScore();
        bestNation = i;
      }
    }
    if (best <= firstValue * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 0x12, &formatText);
    g_pSimMgr->GetString(0x2753, 0x13, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 1, 0);
    advisoryShown = 1;
  } break;

  case 4: {
    int firstValue = g_apNationStates[activeNation]->SumNavyOrderPriorityForNationSlot86();
    int best = firstValue;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (i != activeNation && g_pSimMgr->IsNationSlotEligibleForEventProcessing(i) != 0 &&
          g_apNationStates[i]->SumNavyOrderPriorityForNationSlot86() > best) {
        best = g_apNationStates[i]->SumNavyOrderPriorityForNationSlot86();
        bestNation = i;
      }
    }
    if (best <= firstValue * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 0x14, &formatText);
    g_pSimMgr->GetString(0x2753, 0x15, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        5, formatText, message, &g_cstrNationComparisonMessageStore, 1, 0);
    advisoryShown = 1;
  } break;

  default:
    break;
  }

  return advisoryShown;
}

// Once per turn tick, show the active nation's turn alerts through the localized
// message dispatcher. The first two (mission-score comparison) alerts suppress every
// later block; the remaining blocks are individually gated on turn-flow flags.
// FUNCTION: IMPERIALISM 0x00502b60
char ShowTurnAlertsForActiveNation() {
  short nationId = g_pSimMgr->GetActiveNationId();
  CString titleText;
  CString bodyText;
  CString scratchC;
  CString scratchD;
  char anyAlertShown = 0;
  int stormOutA;
  TCity* city = (g_apNationStates[nationId] != 0) ? g_apNationStates[nationId]->city : 0;
  int stormOutB;
  stormOutA = stormOutB = 0;
  short currentTick = g_pSimMgr->GetTurnTickSlot3C();
  if (g_pSimMgr->preferenceValues[8] == 0) {
    return 0;
  }
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return 0;
  }
  if (g_lastTurnAlertTick_006a31c0 == currentTick) {
    return 0;
  }
  if (currentTick == 1) {
    return 0;
  }

  if (g_apNationStates[nationId]->CompareMissionScoreVariantsByMode(0) != 0) {
    g_pSimMgr->GetString(0x2753, 0x28, &titleText);
    g_pSimMgr->GetString(0x2753, 0x29, &bodyText);
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        3, CString(titleText), CString(bodyText), &g_cstrNationComparisonMessageStore, 1, 0);
    anyAlertShown = 1;
  }
  if (g_apNationStates[nationId]->CompareMissionScoreVariantsByMode(1) != 0) {
    g_pSimMgr->GetString(0x2753, 0x2a, &titleText);
    g_pSimMgr->GetString(0x2753, 0x2b, &bodyText);
    g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
        3, CString(titleText), CString(bodyText), &g_cstrNationComparisonMessageStore, 1, 0);
    anyAlertShown = 1;
  }
  if (anyAlertShown == 0) {
    if (g_pSimMgr->TestTurnFlowStatusFlagMask(1) == 0) {
      short promptCode = g_apNationStates[nationId]->ComputeTreasuryStatusPromptCode();
      if (promptCode != 0) {
        g_pSimMgr->GetString(0x2753, promptCode - 1, &titleText);
        g_pSimMgr->GetString(0x2753, promptCode, &bodyText);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            5, CString(titleText), CString(bodyText), &g_cstrNationComparisonMessageStore, 0, 0);
        anyAlertShown = 1;
      }
    }
    if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x10) == 0) {
      if (g_apNationStates[nationId]->HasAnyCommodityRecordBelowStepValue() != 0) {
        g_pSimMgr->GetString(0x2753, 0x46, &titleText);
        g_pSimMgr->GetString(0x2753, 0x47, &bodyText);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            5, CString(titleText), CString(bodyText), &g_cstrNationComparisonMessageStore, 2, 0);
        anyAlertShown = 1;
      }
    }
    if (g_pSimMgr->TestTurnFlowStatusFlagMask(0x1000) == 0) {
      if (g_apNationStates[nationId]->AnyNeedCurrentExceedsTargetWhenCapMismatch() != 0) {
        g_pSimMgr->GetString(0x2753, 0x22, &titleText);
        g_pSimMgr->GetString(0x2753, 0x23, &bodyText);
        g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
            5, CString(titleText), CString(bodyText), &g_cstrNationComparisonMessageStore, 2, 0);
        anyAlertShown = 1;
      }
    }
    city->productionSummary1d8->OrphanLeaf_NoCall_Ins111_004b6260(
        reinterpret_cast<short*>(&stormOutB), reinterpret_cast<unsigned short*>(&stormOutA));
    if (*reinterpret_cast<short*>(&stormOutA) != 0) {
      g_pSimMgr->GetString(0x2753, 0x20, &titleText);
      g_pSimMgr->GetString(0x2753, 0x21, &bodyText);
      g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplate(
          5, CString(titleText), CString(bodyText), &g_cstrNationComparisonMessageStore, 2, 0);
      anyAlertShown = 1;
    }
  }
  g_lastTurnAlertTick_006a31c0 = currentTick;
  return anyAlertShown;
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
    if (eventCode != 0x2103 || g_bMultiplayerScenarioSetupActive == 0) {
      int index = 1;
      while (!nationAlreadyCurrent && activateCandidate == 0) {
        if (indexList == 0 || index > GetSortedPtrListEntryCount(indexList)) {
          break;
        }
        HelpSetRecord* entry =
            static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
        if (entry->contextId == eventCode) {
          // NOT GetActiveNationId — original loads ECX from g_pSimMgr and
          // dispatches vtable slot 0x3c (GetTurnTickSlot3C), same call as the currentTurn
          // check above. entry->rank stores a turn tick here, not a nation id.
          const short currentTick = g_pSimMgr->GetTurnTickSlot3C();
          if (entry->rank == currentTick) {
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

// FUNCTION: IMPERIALISM 0x00503320
void THelpMgr::SelectAndActivatePendingEventType1A0A() {
  for (int index = 1; index <= GetSortedPtrListEntryCount(indexList); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->contextId == 0x1a0a) {
      ActivatePendingEventAndRefreshView(record);
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00503370
void THelpMgr::SelectAndActivatePendingEventTypeOffsetFrom1A0B(int idx) {
  short targetContextId = static_cast<short>(idx + 0x1a0b);
  for (int index = 1; index <= GetSortedPtrListEntryCount(indexList); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->contextId == targetContextId) {
      ActivatePendingEventAndRefreshView(record);
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005033e0
void THelpMgr::NoOpDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                                   int acceptedFlag) {
  (void)policyOrGrant;
  (void)targetNation;
  (void)acceptedFlag;
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
  pendingEntry->rank = g_pSimMgr->GetActiveNationId();
  // Full dialog refresh path deferred; mark the help-set entry seen/current-nation.
}

// FUNCTION: IMPERIALISM 0x00503b90
void THelpMgr::CycleTradeScreenMode0To2() {
  if (helpIndexReady == 0) {
    helpIndexReady = 1;
  } else if (helpIndexReady == 1) {
    helpIndexReady = 2;
  } else if (helpIndexReady == 2) {
    helpIndexReady = 0;
  }
}
