#include "game/ui_core/THelpMgr.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/THelpPicture.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TPtrList.h"
#include "game/ui_core/TStaticText.h"
#include "game/city/TCity.h"
#include "game/city/TPopulationMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_screens/TTerrainHelpPicture.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TViewMgr.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/ui_screens/turn_flow_cooldown.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/military/TMilitaryUnit.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/core/TStream.h"
#include "game/core/stream_byteswap.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_text_label_helpers_decls.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
namespace {
int g_runtimeCapitolDangerEvaluationCount;
bool g_runtimeCapitolDangerEvaluatedAtPeace;
int g_runtimeCapitolDangerThreatMask;
int g_runtimeCapitolDangerDisplayedMask;
short g_runtimeTurnAlertBodyIndexes[6];
int g_runtimeTurnAlertCount;
bool g_runtimeTurnAlertObservationOnly;

void RecordTurnAlertForRuntimeTest(short bodyIndex) {
  ASSERT(g_runtimeTurnAlertCount < 6);
  g_runtimeTurnAlertBodyIndexes[g_runtimeTurnAlertCount++] = bodyIndex;
}
} // namespace

void ResetCapitolDangerWarningObservationForRuntimeTest() {
  g_runtimeCapitolDangerEvaluationCount = 0;
  g_runtimeCapitolDangerEvaluatedAtPeace = false;
  g_runtimeCapitolDangerThreatMask = 0;
  g_runtimeCapitolDangerDisplayedMask = 0;
}

int CapitolDangerWarningEvaluationCountForRuntimeTest() {
  return g_runtimeCapitolDangerEvaluationCount;
}

bool WasCapitolDangerWarningEvaluatedAtPeaceForRuntimeTest() {
  return g_runtimeCapitolDangerEvaluatedAtPeace;
}

int CapitolDangerThreatMaskForRuntimeTest() {
  return g_runtimeCapitolDangerThreatMask;
}

int CapitolDangerDisplayedMaskForRuntimeTest() {
  return g_runtimeCapitolDangerDisplayedMask;
}

void ResetTurnAlertObservationForRuntimeTest() {
  g_runtimeTurnAlertCount = 0;
}

int TurnAlertObservationCountForRuntimeTest() {
  return g_runtimeTurnAlertCount;
}

short TurnAlertBodyIndexForRuntimeTest(int index) {
  ASSERT(index >= 0 && index < g_runtimeTurnAlertCount);
  return g_runtimeTurnAlertBodyIndexes[index];
}

void SetTurnAlertObservationOnlyForRuntimeTest(bool enabled) {
  g_runtimeTurnAlertObservationOnly = enabled;
}
#endif

IMPLEMENT_DYNCREATE(THelpMgr, TObject)

// FUNCTION: IMPERIALISM 0x005005e0
THelpMgr::THelpMgr() : TObject() {
  pendingDialogView8 = 0;
  pendingDialogViewC = 0;
  tradeAdviceDetailLevel = 0;
  unusedInitializedState1A = 0;
  unusedInitializedState1E = 0;
  unusedInitializedState22 = 0;
  unusedInitializedState26 = 0;
  unusedInitializedState2A = 0;
  unusedInitializedState2C = 0;
  for (int i = 0; i < 5; ++i) {
    civilianCompletionCounts[i] = 0;
  }
  indexList = NULL;
}

// FUNCTION: IMPERIALISM 0x00500660
THelpMgr::~THelpMgr() {}

// FUNCTION: IMPERIALISM 0x00500680
void THelpMgr::IHelpMgr() {
  tradeAdviceDetailLevel = 1;
  TPtrList* list = new TPtrList();
  list->recordSize = sizeof(HelpSetRecord);
  indexList = list;
  if (!g_bMultiplayerScenarioSetupActive) {
    HelpSetRecord record;
#define INSERT_HELP_SET(helpBase, previousBase, nextBase, eventContext, entryRank, topics)         \
  record.helpResourceBaseId = helpBase;                                                            \
  record.previousHelpResourceBaseId = previousBase;                                                \
  record.nextHelpResourceBaseId = nextBase;                                                        \
  record.contextId = eventContext;                                                                 \
  record.rank = entryRank;                                                                         \
  record.flagByte = 0;                                                                             \
  record.topicCount = topics;                                                                      \
  indexList->InsertCopiedRecordSortedByComparator(&record)

    INSERT_HELP_SET(0x0bc2, 0x0000, 0x0bcc, 0x07dd, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0bcc, 0x0bc2, 0x0c94, 0x07dd, 0x0002, 0x0005);
    INSERT_HELP_SET(0x0bd6, 0x0000, 0x0c44, 0x07db, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0bea, 0x0000, 0x0bf4, 0x07d9, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0bf4, 0x0bea, 0x0000, 0x07d9, 0x0003, 0x0004);
    INSERT_HELP_SET(0x0bfe, 0x0000, 0x0c26, 0x07d8, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0c08, 0x0000, 0x0000, 0x08fc, 0x0001, 0x0004);
    INSERT_HELP_SET(0x0c12, 0x0000, 0x0c1c, 0x1a0a, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0c1c, 0x0c12, 0x0cc6, 0x1a0a, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0c26, 0x0bfe, 0x0000, 0x07d8, 0x0002, 0x0005);
    INSERT_HELP_SET(0x0c30, 0x0000, 0x0000, 0x2134, 0x0001, 0x0004);
    INSERT_HELP_SET(0x0c3a, 0x0000, 0x0000, 0x07de, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0c44, 0x0bd6, 0x0c4e, 0x07db, 0x0002, 0x0005);
    INSERT_HELP_SET(0x0c4e, 0x0c44, 0x0000, 0x07db, 0x0003, 0x0005);
    INSERT_HELP_SET(0x0c62, 0x0000, 0x0000, 0x0547, 0x0001, 0x0003);
    INSERT_HELP_SET(0x0c6c, 0x0000, 0x0000, 0x0ed8, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0c76, 0x0000, 0x0000, 0x07e0, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0c8a, 0x0000, 0x0000, 0x2260, 0x0001, 0x0004);
    INSERT_HELP_SET(0x0c94, 0x0bcc, 0x0c9e, 0x07dd, 0x0003, 0x0005);
    INSERT_HELP_SET(0x0c9e, 0x0c94, 0x0ca8, 0x07dd, 0x0004, 0x0005);
    INSERT_HELP_SET(0x0ca8, 0x0c9e, 0x0000, 0x07dd, 0x0005, 0x0005);
    INSERT_HELP_SET(0x0cb2, 0x0000, 0x0000, 0x1036, 0x0000, 0x0003);
    INSERT_HELP_SET(0x0cbc, 0x0000, 0x0000, 0x2103, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0cc6, 0x0c1c, 0x0000, 0x1a0a, 0x0001, 0x0002);
    INSERT_HELP_SET(0x0cd0, 0x0000, 0x0000, 0x03b8, 0x0001, 0x0005);
    INSERT_HELP_SET(0x0cda, 0x0000, 0x0000, 0x10cc, 0x0001, 0x0002);
    INSERT_HELP_SET(0x0cee, 0x0000, 0x0000, 0x1a0b, 0x0001, 0x0001);
    INSERT_HELP_SET(0x0d0c, 0x0000, 0x0000, 0x1a0c, 0x0001, 0x0001);
    INSERT_HELP_SET(0x0d16, 0x0000, 0x0000, 0x1a0d, 0x0001, 0x0001);
    INSERT_HELP_SET(0x0000, 0x0000, 0x0bb9, 0x0000, 0x0000, 0x0003);
#undef INSERT_HELP_SET
  }
}

// FUNCTION: IMPERIALISM 0x00500f10
void THelpMgr::ResetHelpSetRanksAndFlags() {
  for (int index = 1; index <= indexList->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    record->rank = 0;
    record->flagByte = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00500f50
void THelpMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  indexList->InvokePtrListResetHook();
  indexList->ReadFrom(stream);
  if (g_nSaveFormatVersion >= 0x2b) {
    stream->ReadBytes(civilianCompletionCounts, sizeof(civilianCompletionCounts));
    SwapShortArrayBytes(civilianCompletionCounts, 5);
  }
  if (g_nSaveFormatVersion >= 0x37) {
    stream->ReadBytes(&tradeAdviceDetailLevel, 2);
  }
}

// FUNCTION: IMPERIALISM 0x00500fe0
void THelpMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  indexList->WriteTo(stream);
  WriteShortArrayElems(stream, civilianCompletionCounts, 5);
  stream->WriteBytes(&tradeAdviceDetailLevel, 2);
}

// FUNCTION: IMPERIALISM 0x00501070
void THelpMgr::Free() {
  if (indexList != 0) {
    indexList->ReleasePtrList();
  }
  indexList = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x005010b0
void THelpMgr::SelectAndActivatePendingEventForCurrentView() {
  HelpSetRecord* best = NULL;             // lowest-rank unflagged match
  HelpSetRecord* flaggedCandidate = NULL; // context match with flagByte set
  HelpSetRecord* zeroIdCandidate =
      NULL; // context match, rank>=threshold, previousHelpResourceBaseId==0
  short threshold = g_pSimMgr->GetEconomicTurn();
  short contextId = g_pViewMgr->currentTurnEventCode;
  for (int index = 1; index <= indexList->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->contextId == contextId) {
      if (record->flagByte != 0) {
        flaggedCandidate = record;
      } else if (record->rank >= threshold) {
        if (record->previousHelpResourceBaseId == 0) {
          zeroIdCandidate = record;
        }
      } else {
        best = record;
        threshold = record->rank;
      }
    }
  }
  if (best != NULL) {
    ShowHelpSet(best);
    return;
  }
  HelpSetRecord* fallback = flaggedCandidate;
  if (fallback == NULL) {
    fallback = zeroIdCandidate;
  }
  if (fallback != NULL) {
    ShowHelpSet(fallback);
  }
}

// FUNCTION: IMPERIALISM 0x005011a0
void THelpMgr::HandlePostDispatchTurnStateEventUpdates() {
  const short nationId = g_pSimMgr->GetPlayerCountry();
  const eGamePhaseNewStyle phase = g_pSimMgr->mode;
  if (phase != kGamePhaseNews) {
    if (phase == kGamePhaseOptionalCityScreen && g_pSimMgr->preferenceValues[8] != 0) {
      if (g_nTurnFlowNationComparisonAdvisoryTick < g_pSimMgr->GetEconomicTurn()) {
        if (ShowPeriodicNationComparisonAdvisoryIfNeeded()) {
          g_nTurnFlowNationComparisonAdvisoryTick = g_pSimMgr->GetEconomicTurn();
        }
      }
    }
    return;
  }
  // No null check in the original: the news phase guarantees the active nation slot.
  g_apNationStates[nationId]->DispatchPendingStatusPrompts();
  g_apNationStates[nationId]->BuildGreatPowerTurnMessageSummaryAndDispatch();
  if (g_pSimMgr->preferenceValues[8] != 0) {
    if (DispatchTurnStateSpecialAdvisoriesAndReturnCount() < 2) {
      ShowPeriodicCapabilityReminderIfNeeded();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00501270
short THelpMgr::DispatchTurnStateSpecialAdvisoriesAndReturnCount() {
  g_pSimMgr->GetEconomicTurn();
  short activeNation = g_pSimMgr->GetPlayerCountry();
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
  TPtrList* queue = g_apNationStates[activeNationIndex]->turnEventQueue;
  int i;
  for (i = 1; i <= queue->GetSize(); ++i) {
    short* eventRecord = static_cast<short*>(queue->GetPtrListEntryByOneBasedIndex(i));
    switch (eventRecord[0]) {
    case 0x13b: {
      short standingNation = g_pDiplomacyTurnStateManager->GetFavoriteTradePartner(eventRecord[1]);
      if (standingNation != activeNation) {
        g_apNationStates[standingNation]->FormatOverlayTerrainLabelText(&nationNameText);
        g_apSecondaryNationStateSlots[eventRecord[1]]->FormatOverlayTerrainLabelText(
            &minorNameText);
        g_pSimMgr->GetString(0x2753, 0x1e, &titleText);
        g_pSimMgr->GetString(0x2753, 0x1f, &templateText);
        scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationNameText),
                               static_cast<LPCSTR>(minorNameText));
        g_pViewMgr->ModalMessage(3, titleText, formattedText, g_ptNationComparisonModalMessage, 0,
                                 0);
        ++advisoryCount;
      }
      break;
    }
    case 0x13a: {
      short standingNation =
          static_cast<short>(g_pDiplomacyTurnStateManager->GetFavorite(eventRecord[1], 1));
      if (standingNation != activeNation) {
        g_apNationStates[standingNation]->FormatOverlayTerrainLabelText(&nationNameText);
        g_apSecondaryNationStateSlots[eventRecord[1]]->FormatOverlayTerrainLabelText(
            &minorNameText);
        g_pSimMgr->GetString(0x2753, 0x1a, &titleText);
        g_pSimMgr->GetString(0x2753, 0x1b, &templateText);
        scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(minorNameText),
                               static_cast<LPCSTR>(nationNameText));
        g_pViewMgr->ModalMessage(3, titleText, formattedText, g_ptNationComparisonModalMessage, 0,
                                 0);
        ++advisoryCount;
      }
      break;
    }
    case kDiplomacyProposalDeclareWar: {
      g_apNationStates[eventRecord[1]]->FormatOverlayTerrainLabelText(&nationNameText);
      g_pSimMgr->GetString(0x2753, 0x1c, &titleText);
      g_pSimMgr->GetString(0x2753, 0x1d, &templateText);
      scanBracketExpressions(g_pSimMgr, &formattedText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(nationNameText));
      g_pViewMgr->ModalMessage(3, titleText, formattedText, g_ptNationComparisonModalMessage, 0, 0);
      ++advisoryCount;
      break;
    }
    }
  }

  CString contextMessageText(g_pszEmptyTextPointer);
  if (g_apNationStates[activeNationIndex]->BuildGreatPowerMapContextTriggeredNationEventMessages(
          &contextMessageText)) {
    g_pSimMgr->GetString(0x2753, 0x3c, &titleText);
    g_pSimMgr->GetString(0x2753, 0x3d, &templateText);
    CString combinedText = templateText + contextMessageText;
    formattedText = combinedText;
    g_pViewMgr->ModalMessage(3, titleText, formattedText, g_ptNationComparisonModalMessage, 1, 0);
  }

  contextMessageText = CString(g_pszEmptyTextPointer);
  if (g_apNationStates[activeNationIndex]->BuildGreatPowerEligibleNationEventMessagesFromLinkedList(
          &contextMessageText)) {
    g_pSimMgr->GetString(0x2753, 0x42, &titleText);
    g_pSimMgr->GetString(0x2753, 0x43, &templateText);
    templateText += contextMessageText;
    g_pViewMgr->ModalMessage(3, titleText, templateText, g_ptNationComparisonModalMessage, 1, 0);
  }

  if (activeCity != 0 && activeCity->foodSubstitutionCount != 0 &&
      activeCity->starvationPopulationLoss == 0) {
    g_pSimMgr->GetString(0x2753, 0x16, &titleText);
    g_pSimMgr->GetString(0x2753, 0x17, &templateText);
    g_pViewMgr->ModalMessage(5, titleText, templateText, g_ptNationComparisonModalMessage, 2, 0);
    ++advisoryCount;
  }
  return advisoryCount;
}

// FUNCTION: IMPERIALISM 0x00501a20
void THelpMgr::ShowPeriodicCapabilityReminderIfNeeded() {
  short tickMod = static_cast<short>(g_pSimMgr->GetEconomicTurn() % 10);
  short activeNation = g_pSimMgr->GetPlayerCountry();
  CString titleText;
  CString messageText;
  // Constructed and destroyed unused in the original (EH state 2).
  CString unusedText;
  if (tickMod == 0 || tickMod == 5) {
    if (g_pTechMgr->orderCapRows277[activeNation].techStatusByTechId[g_pTechMgr->marker262] == 0) {
      g_pSimMgr->GetString(0x2753, 0x18, &titleText);
      g_pSimMgr->GetString(0x2753, 0x19, &messageText);
      g_pViewMgr->ModalMessage(5, titleText, messageText, g_ptNationComparisonModalMessage, 2, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00501be0
bool THelpMgr::ShowPeriodicNationComparisonAdvisoryIfNeeded() {
  short activeNation = g_pSimMgr->GetPlayerCountry();
  CString formatText;
  CString templateText;
  CString nationName;
  CString message;
  bool advisoryShown = false;

  switch (static_cast<short>(g_pSimMgr->GetEconomicTurn() % 10)) {
  case 0: {
    TGreatPower* active = g_apNationStates[activeNation];
    short best = (active != 0) ? active->transportCapacity : 0;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(i)) {
        TGreatPower* nation = g_apNationStates[i];
        short value = (nation != 0) ? nation->transportCapacity : 0;
        if (value > best) {
          best = (nation != 0) ? nation->transportCapacity : 0;
          bestNation = i;
        }
      }
    }
    TGreatPower* mine = g_apNationStates[activeNation];
    short mineValue = (mine != 0) ? mine->transportCapacity : 0;
    if (best <= mineValue * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 0, &formatText);
    g_pSimMgr->GetString(0x2753, 1, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
    advisoryShown = true;
  } break;

  case 3: {
    short best = g_apNationStates[activeNation]->merchantCapacity;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(i) && g_apNationStates[i]->merchantCapacity > best) {
        best = g_apNationStates[i]->merchantCapacity;
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->merchantCapacity * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 2, &formatText);
    g_pSimMgr->GetString(0x2753, 3, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 0, 0);
    advisoryShown = true;
  } break;

  case 6: {
    short best = g_apNationStates[activeNation]->ComputeNationRuntimeAdvisoryMetricCase6();
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(i) &&
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
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
    advisoryShown = true;
  } break;

  case 2: {
    int best = g_apNationStates[activeNation]->GetBuildingCapacity(0);
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(i) && g_apNationStates[i]->GetBuildingCapacity(0) > best) {
        best = g_apNationStates[i]->GetBuildingCapacity(0);
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->GetBuildingCapacity(0) * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 6, &formatText);
    g_pSimMgr->GetString(0x2753, 7, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
    advisoryShown = true;
  } break;

  case 5: {
    int best = g_apNationStates[activeNation]->GetBuildingCapacity(2);
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(i) && g_apNationStates[i]->GetBuildingCapacity(2) > best) {
        best = g_apNationStates[i]->GetBuildingCapacity(2);
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->GetBuildingCapacity(2) * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 8, &formatText);
    g_pSimMgr->GetString(0x2753, 9, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
    advisoryShown = true;
  } break;

  case 7: {
    int best = g_apNationStates[activeNation]->GetBuildingCapacity(4);
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (g_pSimMgr->ReallyInTheGame(i) && g_apNationStates[i]->GetBuildingCapacity(4) > best) {
        best = g_apNationStates[i]->GetBuildingCapacity(4);
        bestNation = i;
      }
    }
    if (best <= g_apNationStates[activeNation]->GetBuildingCapacity(4) * 2) {
      break;
    }
    g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
    g_pSimMgr->GetString(0x2753, 0xa, &formatText);
    g_pSimMgr->GetString(0x2753, 0xb, &templateText);
    scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(nationName));
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
    advisoryShown = true;
  } break;

  case 8: {
    if (g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] == 0) {
      break;
    }
    if (g_apNationStates[activeNation]->GetBuildingCapacity(6) == 0) {
      int best = 0;
      short bestNation = activeNation;
      for (short i = 0; i < 7; ++i) {
        if (g_pSimMgr->ReallyInTheGame(i) && g_apNationStates[i]->GetBuildingCapacity(6) > best) {
          best = g_apNationStates[i]->GetBuildingCapacity(6);
          bestNation = i;
        }
      }
      if (best <= 4) {
        break;
      }
      if (g_pTechMgr->orderCapRows277[activeNation].techStatusByTechId[0x13] != 0) {
        g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
        g_pSimMgr->GetString(0x2753, 0xc, &formatText);
        g_pSimMgr->GetString(0x2753, 0xd, &templateText);
        scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationName));
        g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
        advisoryShown = true;
      } else {
        g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
        g_pSimMgr->GetString(0x2753, 0xe, &formatText);
        g_pSimMgr->GetString(0x2753, 0xf, &templateText);
        scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(nationName));
        g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
        advisoryShown = true;
      }
    } else {
      int best = g_apNationStates[activeNation]->GetBuildingCapacity(6);
      short bestNation = activeNation;
      for (short i = 0; i < 7; ++i) {
        if (g_pSimMgr->ReallyInTheGame(i) && g_apNationStates[i]->GetBuildingCapacity(6) > best) {
          best = g_apNationStates[i]->GetBuildingCapacity(6);
          bestNation = i;
        }
      }
      if (best <= g_apNationStates[activeNation]->GetBuildingCapacity(6) * 2) {
        break;
      }
      g_apNationStates[bestNation]->FormatOverlayTerrainLabelText(&nationName);
      g_pSimMgr->GetString(0x2753, 0x10, &formatText);
      g_pSimMgr->GetString(0x2753, 0x11, &templateText);
      scanBracketExpressions(g_pSimMgr, &message, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(nationName));
      g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 2, 0);
      advisoryShown = true;
    }
  } break;

  case 1: {
    int firstValue = g_apNationStates[activeNation]->ComputeSelectedMilitaryPowerScore();
    int best = firstValue;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (i != activeNation && g_pSimMgr->ReallyInTheGame(i) &&
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
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 1, 0);
    advisoryShown = true;
  } break;

  case 4: {
    int firstValue = g_apNationStates[activeNation]->GetArmsInNavy();
    int best = firstValue;
    short bestNation = activeNation;
    for (short i = 0; i < 7; ++i) {
      if (i != activeNation && g_pSimMgr->ReallyInTheGame(i) &&
          g_apNationStates[i]->GetArmsInNavy() > best) {
        best = g_apNationStates[i]->GetArmsInNavy();
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
    g_pViewMgr->ModalMessage(5, formatText, message, g_ptNationComparisonModalMessage, 1, 0);
    advisoryShown = true;
  } break;

  default:
    break;
  }

  return advisoryShown;
}

// FUNCTION: IMPERIALISM 0x00502b60
bool ShowTurnAlertsForActiveNation() {
  short nationId = g_pSimMgr->GetPlayerCountry();
  CString titleText;
  CString bodyText;
  CString scratchC;
  CString scratchD;
  bool anyAlertShown = false;
  short starvationCount;
  TCity* city = (g_apNationStates[nationId] != 0) ? g_apNationStates[nationId]->city : 0;
  short foodSubstitutionCount;
  starvationCount = foodSubstitutionCount = 0;
  short currentTick = g_pSimMgr->GetEconomicTurn();
  if (g_pSimMgr->preferenceValues[8] == 0) {
    return false;
  }
  if (IsTurnFlowCooldownActiveAndResetExpiredState()) {
    return false;
  }
  if (g_lastTurnAlertTick == currentTick) {
    return false;
  }
  if (currentTick == 1) {
    return false;
  }

#ifdef IMPERIALISM_RUNTIME_TESTS
  bool nationAtWar = false;
  for (int otherNation = 0; otherNation < 7; ++otherNation) {
    if (otherNation != nationId &&
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, otherNation)) {
      nationAtWar = true;
    }
  }
  const char landCapitolThreat = g_apNationStates[nationId]->IsCapitolThreatened(0);
  ++g_runtimeCapitolDangerEvaluationCount;
  g_runtimeCapitolDangerEvaluatedAtPeace = !nationAtWar;
  g_runtimeCapitolDangerThreatMask = landCapitolThreat != 0 ? 1 : 0;
  g_runtimeCapitolDangerDisplayedMask = 0;
  if (landCapitolThreat != 0) {
#else
  if (g_apNationStates[nationId]->IsCapitolThreatened(0)) {
#endif
#ifdef IMPERIALISM_RUNTIME_TESTS
    g_runtimeCapitolDangerDisplayedMask |= 1;
#endif
    g_pSimMgr->GetString(0x2753, 0x28, &titleText);
    g_pSimMgr->GetString(0x2753, 0x29, &bodyText);
#ifdef IMPERIALISM_RUNTIME_TESTS
    RecordTurnAlertForRuntimeTest(0x29);
    if (!g_runtimeTurnAlertObservationOnly) {
#endif
      g_pViewMgr->ModalMessage(3, CString(titleText), CString(bodyText),
                               g_ptNationComparisonModalMessage, 1, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
    }
#endif
    anyAlertShown = true;
  }
#ifdef IMPERIALISM_RUNTIME_TESTS
  const char navalCapitolThreat = g_apNationStates[nationId]->IsCapitolThreatened(1);
  if (navalCapitolThreat != 0) {
    g_runtimeCapitolDangerThreatMask |= 2;
#else
  if (g_apNationStates[nationId]->IsCapitolThreatened(1)) {
#endif
#ifdef IMPERIALISM_RUNTIME_TESTS
    g_runtimeCapitolDangerDisplayedMask |= 2;
#endif
    g_pSimMgr->GetString(0x2753, 0x2a, &titleText);
    g_pSimMgr->GetString(0x2753, 0x2b, &bodyText);
#ifdef IMPERIALISM_RUNTIME_TESTS
    RecordTurnAlertForRuntimeTest(0x2b);
    if (!g_runtimeTurnAlertObservationOnly) {
#endif
      g_pViewMgr->ModalMessage(3, CString(titleText), CString(bodyText),
                               g_ptNationComparisonModalMessage, 1, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
    }
#endif
    anyAlertShown = true;
  }
  if (!anyAlertShown) {
    if (!g_pSimMgr->TestTurnFlowStatusFlagMask(1)) {
      short promptCode = g_apNationStates[nationId]->ComputeTreasuryStatusPromptCode();
      if (promptCode != 0) {
        g_pSimMgr->GetString(0x2753, promptCode - 1, &titleText);
        g_pSimMgr->GetString(0x2753, promptCode, &bodyText);
#ifdef IMPERIALISM_RUNTIME_TESTS
        RecordTurnAlertForRuntimeTest(promptCode);
        if (!g_runtimeTurnAlertObservationOnly) {
#endif
          g_pViewMgr->ModalMessage(5, CString(titleText), CString(bodyText),
                                   g_ptNationComparisonModalMessage, 0, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
        }
#endif
        anyAlertShown = true;
      }
    }
    if (!g_pSimMgr->TestTurnFlowStatusFlagMask(0x10)) {
      if (g_apNationStates[nationId]->HasAnyCommodityRecordBelowStepValue()) {
        g_pSimMgr->GetString(0x2753, 0x46, &titleText);
        g_pSimMgr->GetString(0x2753, 0x47, &bodyText);
#ifdef IMPERIALISM_RUNTIME_TESTS
        RecordTurnAlertForRuntimeTest(0x47);
        if (!g_runtimeTurnAlertObservationOnly) {
#endif
          g_pViewMgr->ModalMessage(5, CString(titleText), CString(bodyText),
                                   g_ptNationComparisonModalMessage, 2, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
        }
#endif
        anyAlertShown = true;
      }
    }
    if (!g_pSimMgr->TestTurnFlowStatusFlagMask(0x1000)) {
      if (g_apNationStates[nationId]->AnyNeedCurrentExceedsTargetWhenCapMismatch()) {
        g_pSimMgr->GetString(0x2753, 0x22, &titleText);
        g_pSimMgr->GetString(0x2753, 0x23, &bodyText);
#ifdef IMPERIALISM_RUNTIME_TESTS
        RecordTurnAlertForRuntimeTest(0x23);
        if (!g_runtimeTurnAlertObservationOnly) {
#endif
          g_pViewMgr->ModalMessage(5, CString(titleText), CString(bodyText),
                                   g_ptNationComparisonModalMessage, 2, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
        }
#endif
        anyAlertShown = true;
      }
    }
    city->productionSummary->PretendToEat(foodSubstitutionCount, starvationCount);
    if (starvationCount != 0) {
      g_pSimMgr->GetString(0x2753, 0x20, &titleText);
      g_pSimMgr->GetString(0x2753, 0x21, &bodyText);
#ifdef IMPERIALISM_RUNTIME_TESTS
      RecordTurnAlertForRuntimeTest(0x21);
      if (!g_runtimeTurnAlertObservationOnly) {
#endif
        g_pViewMgr->ModalMessage(5, CString(titleText), CString(bodyText),
                                 g_ptNationComparisonModalMessage, 2, 0);
#ifdef IMPERIALISM_RUNTIME_TESTS
      }
#endif
      anyAlertShown = true;
    }
  }
  g_lastTurnAlertTick = currentTick;
  return anyAlertShown;
}

// FUNCTION: IMPERIALISM 0x005031c0
bool THelpMgr::HandlePendingEventActivationByCode(TurnEventCodeStorage eventCode) {
  bool activateCandidate = false;
  bool nationAlreadyCurrent = false;
  HelpSetRecord* pendingEntry = 0;

  if (eventCode != kTurnEventStrategicMap && eventCode != kTurnEventCitySiteSelector) {
    if (pendingDialogViewC != 0) {
      pendingDialogViewC->CloseAndFree();
      pendingDialogViewC = 0;
    }
  }

  if (g_pSimMgr->preferenceValues[10] == 0) {
    if (pendingDialogView8 != 0) {
      pendingDialogView8->CloseAndFree();
      pendingDialogView8 = 0;
    }
  } else {
    if (eventCode != kTurnEventNewspaperStatus || !g_bMultiplayerScenarioSetupActive) {
      int index = 1;
      while (!nationAlreadyCurrent && !activateCandidate) {
        if (indexList == 0 || index > indexList->GetSize()) {
          break;
        }
        HelpSetRecord* entry =
            static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
        if (entry->contextId == eventCode) {
          const short currentTick = g_pSimMgr->GetEconomicTurn();
          if (entry->rank == currentTick) {
            nationAlreadyCurrent = true;
          } else if (entry->flagByte == 0) {
            activateCandidate = true;
            pendingEntry = entry;
          }
        }
        index++;
      }
    }
    if (activateCandidate && !nationAlreadyCurrent) {
      ShowHelpSet(pendingEntry);
      return activateCandidate;
    }
    if (pendingDialogView8 != 0) {
      pendingDialogView8->CloseAndFree();
      pendingDialogView8 = 0;
    }
  }
  return activateCandidate;
}

// FUNCTION: IMPERIALISM 0x00503320
void THelpMgr::SelectAndActivatePendingEventType1A0A() {
  for (int index = 1; index <= indexList->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->contextId == 0x1a0a) {
      ShowHelpSet(record);
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00503370
void THelpMgr::SelectAndActivatePendingEventTypeOffsetFrom1A0B(int idx) {
  short targetContextId = static_cast<short>(idx + 0x1a0b);
  for (int index = 1; index <= indexList->GetSize(); ++index) {
    HelpSetRecord* record =
        static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->contextId == targetContextId) {
      ShowHelpSet(record);
      return;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005033e0
void THelpMgr::NoOpDiplomacyPolicyStateChangedHook(int policyOrGrant, int targetNation,
                                                   int acceptedFlag) {}

// FUNCTION: IMPERIALISM 0x00503400
void THelpMgr::HandlePostPendingEventActivationNoOp(TurnEventCodeStorage eventCode) {}

// FUNCTION: IMPERIALISM 0x00503420
void THelpMgr::ShowHelpSet(HelpSetRecord* pendingEntry) {
  CString titleText;
  pendingEntry->flagByte = 1;
  pendingEntry->rank = g_pSimMgr->GetPlayerCountry();

  TextStyle titleStyle;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 12, 0x2b67, 1);

  if (pendingDialogView8 == 0) {
    pendingDialogView8 = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventHelpMessage));
    if (pendingDialogView8 == 0) {
      FailNilPointerWithAssert(s_SourcePathUHelpMgr, 0x5cd);
    }

    CPoint placement;
    g_pViewMgr->GetTopLeftFor(pendingDialogView8, &placement);
    pendingDialogView8->Locate(placement, false);
    pendingDialogView8->Open();
  }

  THelpPicture* helpPicture =
      static_cast<THelpPicture*>(pendingDialogView8->ResolveControlByTag(kControlTagDialog));
  helpPicture->currentHelpSet = pendingEntry;

  CString emptyTitle(g_pszEmptyTextPointer);
  pendingDialogView8->SetTitle(&emptyTitle);

  int helpBookIndex = g_pViewMgr->ClassifyTurnStateForOverlayMode();
  if (pendingEntry->contextId == 0x1a0b) {
    helpBookIndex = 0;
  } else if (pendingEntry->contextId == 0x1a0d) {
    helpBookIndex = 2;
  } else if (pendingEntry->contextId == 0x1a0c) {
    helpBookIndex = 1;
  }
  helpPicture->SetPictureRsrcID(static_cast<short>(helpBookIndex + 0xbb8), 0);

  TPicture* coatPicture =
      static_cast<TPicture*>(pendingDialogView8->ResolveControlByTag(kControlTagCoat));
  coatPicture->AssertValid();
  if (coatPicture == 0) {
    FailNilPointerWithAssert(s_SourcePathUHelpMgr, 0x5f0);
  }

  if (g_pSimMgr->GetPlayerCountry() >= 0 && g_pSimMgr->GetPlayerCountry() < 7) {
    coatPicture->SetPictureRsrcID(static_cast<short>(g_pSimMgr->GetPlayerCountry() + 0x251c), 0);
  } else {
    coatPicture->Show(0, 0);
  }

  TStaticText* title = static_cast<TStaticText*>(helpPicture->ResolveControlByTag(kControlTagTitl));
  title->Show(1, 1);
  title->ViewEnable(0, 1);
  title->SetJustification(1, false);
  title->InstallTextStyle(titleStyle, 0);
  BuildUiMessageTextFromBracketTemplate(g_pSimMgr, &titleText, 0x2749, 6, 0x2749,
                                        pendingEntry->contextId);
  title->SetTextAndMaybeRefresh(&titleText, false);
  helpPicture->ShowTopicList();
}

// FUNCTION: IMPERIALISM 0x00503790
char THelpMgr::GetHelpSetRecordFlagByResourceBase(short helpResourceBaseId) {
  HelpSetRecord* record;
  bool found = false;
  int index = 1;
  while (index <= indexList->GetSize()) {
    record = static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->helpResourceBaseId == helpResourceBaseId) {
      found = true;
    }
    ++index;
    if (found) {
      break;
    }
  }
  return record->flagByte;
}

// FUNCTION: IMPERIALISM 0x005037e0
HelpSetRecord* THelpMgr::FindHelpSetRecordByResourceBase(short helpResourceBaseId) {
  HelpSetRecord* record;
  bool found = false;
  int index = 1;
  while (index <= indexList->GetSize()) {
    record = static_cast<HelpSetRecord*>(indexList->GetPtrListEntryByOneBasedIndex(index));
    if (record->helpResourceBaseId == helpResourceBaseId) {
      found = true;
    }
    ++index;
    if (found) {
      break;
    }
  }
  return record;
}

// FUNCTION: IMPERIALISM 0x00503830
bool THelpMgr::IncrementCivilianCompletionCounterAndCheckThreshold(unsigned int index) {
  short* counters = &civilianCompletionCounts[0];
  short threshold = -1;
  switch (index) {
  case 0:
  case 2:
  case 3:
  case 4:
    threshold = 1;
    break;
  case 1:
    ++counters[index];
    return counters[index] == 3;
  }
  ++counters[index];
  return counters[index] == threshold;
}

// FUNCTION: IMPERIALISM 0x005038b0
void THelpMgr::CheckUnitAdvice(TCivUnit* civilianOrderEntry) {
  int titleStringIndex = -1;
  int messageStringIndex = -1;

  if (civilianOrderEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitProspector)) {
    if (civilianOrderEntry->completionMarker == 0x232f && ++civilianCompletionCounts[0] == 1) {
      titleStringIndex = 0x2c;
      messageStringIndex = 0x2d;
    }
  } else if (civilianOrderEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitEngineer)) {
    switch (civilianOrderEntry->completionMarker) {
    case 0x2329:
      if (++civilianCompletionCounts[1] == 3) {
        titleStringIndex = 0x2e;
        messageStringIndex = 0x2f;
      }
      break;
    case 0x232a:
      if (++civilianCompletionCounts[2] == 1) {
        titleStringIndex = 0x32;
        messageStringIndex = 0x33;
      }
      break;
    case 0x232b:
      if (++civilianCompletionCounts[3] == 1) {
        titleStringIndex = 0x34;
        messageStringIndex = 0x35;
      }
      break;
    }
  } else if (++civilianCompletionCounts[4] == 1) {
    titleStringIndex = 0x30;
    messageStringIndex = 0x31;
  }

  if (titleStringIndex != -1) {
    CString titleText;
    CString messageText;
    g_pSimMgr->GetString(0x2753, static_cast<short>(titleStringIndex), &titleText);
    g_pSimMgr->GetString(0x2753, static_cast<short>(messageStringIndex), &messageText);
    g_pViewMgr->ModalMessage(5, titleText, messageText, g_ptNationComparisonModalMessage, 2, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00503ac0
void THelpMgr::EnsureMapActionContextViewAndBuildDefaultTileMenu(int mapContextIndex) {
  if (pendingDialogViewC == 0) {
    pendingDialogViewC = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventTerrainHelp));
    if (pendingDialogViewC == 0) {
      FailNilPointerWithAssert(s_SourcePathUHelpMgr, 0x6c1);
    }

    CPoint placement;
    g_pViewMgr->GetTopLeftFor(pendingDialogViewC, &placement);
    pendingDialogViewC->Locate(placement, false);
    pendingDialogViewC->Open();
  }

  TTerrainHelpPicture* terrainHelp =
      static_cast<TTerrainHelpPicture*>(pendingDialogViewC->ResolveControlByTag(kControlTagDialog));
  terrainHelp->BuildMapTileActionContextMenu(static_cast<short>(mapContextIndex));
}

// FUNCTION: IMPERIALISM 0x00503b90
void THelpMgr::ToggleTradeAdvice() {
  if (tradeAdviceDetailLevel == 0) {
    tradeAdviceDetailLevel = 1;
  } else if (tradeAdviceDetailLevel == 1) {
    tradeAdviceDetailLevel = 2;
  } else if (tradeAdviceDetailLevel == 2) {
    tradeAdviceDetailLevel = 0;
  }
}
