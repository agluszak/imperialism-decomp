#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_tags_screens.h"

#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_core/TLanguageMgr.h"
#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TZone.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

#include <string.h>
// FUNCTION: IMPERIALISM 0x004356e0
TNewspaperView::TNewspaperView() {}

// SYNTHETIC: IMPERIALISM 0x00435710
// TNewspaperView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00435740
TNewspaperView::~TNewspaperView() {}
// SYNTHETIC: IMPERIALISM 0x0055d160
// TNewspaperView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055d1e0
// TNewspaperView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewspaperView, TPicture)

// Base ctor call + vptr store only; the original body is 18 bytes ending in
// `mov eax,esi` return-this.

// Populate the nation-status advisor page: date + special-metric headline children,
// then the 3x3 inter-nation newspaper story grid from the queue manager's pages.
// FUNCTION: IMPERIALISM 0x0055d200
void TNewspaperView::StuffValues(int pageNation) {
  CString tokens[4];
  summaryPageIndex90 = pageNation;
  CString formatText;
  CString panelText;
  CString dateText;
  newsTexStream94 =
      g_pUiViewManager->LoadTableResourceStreamByName(g_pLanguageMgr->GetNewsTexPath());

  TextStyle titleStyle;   // (face 0, 12pt)
  TextStyle featureStyle; // (face 1, 14pt)
  TextStyle plainStyle;   // (face 0, 14pt)
  titleStyle.textColor = 0;
  featureStyle.textColor = 0;
  plainStyle.textColor = 0;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xc, 0x2b67, 2);
  InitializeUiTextStyleDescriptor(&featureStyle, 1, 0xe, 0x2b67, 2);
  InitializeUiTextStyleDescriptor(&plainStyle, 0, 0xe, 0x2b67, 2);

  TStaticText* dateControl =
      static_cast<TStaticText*>(ResolveControlByTag(kControlTagDate)); // 'date'
  dateControl->AssertValid();
  g_pSimMgr->GetSeason(&dateText);
  formatText.Format(g_szDecimalFormat, static_cast<short>(g_pSimMgr->economicTurn / 4) + 0x717);
  panelText = dateText + g_szListSeparator_00695760 + formatText;
  dateControl->SetTextAndMaybeRefresh(&panelText, 1);
  dateControl->InstallTextStyle(titleStyle, 1);

  TStaticText* specialControl =
      static_cast<TStaticText*>(ResolveControlByTag(kControlTagSpec)); // 'spec'
  specialControl->AssertValid();
  if (g_apNationStates[g_pSimMgr->GetActiveNationId()] == 0) {
    panelText = CString(g_szEmptyString);
  } else {
    switch (static_cast<short>(g_pSimMgr->economicTurn % 4)) {
    case 0:
      dateText.Format(g_szDecimalFormat,
                      g_apNationStates[g_pSimMgr->GetActiveNationId()]->escalationCounter);
      g_pSimMgr->GetString(0x275e, 0, &formatText);
      scanBracketExpressions(g_pSimMgr, &panelText, static_cast<LPCSTR>(formatText),
                             static_cast<LPCSTR>(dateText));
      break;
    case 1: {
      int tradeDelta =
          g_pNationInteractionStateManager->ComputeAverageProposalWeightDeltaAcrossCategoryRows();
      dateText.Format(g_szDecimalFormat, tradeDelta);
      if (tradeDelta > 0) {
        dateText = g_szPlusPrefix_00698494 + dateText;
      }
      g_pSimMgr->GetString(0x275e, 1, &formatText);
      scanBracketExpressions(g_pSimMgr, &panelText, static_cast<LPCSTR>(formatText),
                             static_cast<LPCSTR>(dateText));
      break;
    }
    case 2:
      g_pDiplomacyTurnStateManager->RecomputeNationComparativePowerMetrics();
      dateText.Format(
          g_szDecimalFormat,
          g_pDiplomacyTurnStateManager->comparativePowerRows[g_pSimMgr->GetActiveNationId()][3]);
      g_pSimMgr->GetString(0x275e, 2, &formatText);
      scanBracketExpressions(g_pSimMgr, &panelText, static_cast<LPCSTR>(formatText),
                             static_cast<LPCSTR>(dateText));
      break;
    case 3:
      g_pDiplomacyTurnStateManager->RecomputeNationComparativePowerMetrics();
      dateText.Format(
          g_szDecimalFormat,
          g_pDiplomacyTurnStateManager->comparativePowerRows[g_pSimMgr->GetActiveNationId()][0]);
      g_pSimMgr->GetString(0x275e, 3, &formatText);
      scanBracketExpressions(g_pSimMgr, &panelText, static_cast<LPCSTR>(formatText),
                             static_cast<LPCSTR>(dateText));
      break;
    }
  }
  specialControl->SetTextAndMaybeRefresh(&panelText, 1);
  specialControl->InstallTextStyle(titleStyle, 1);

  for (int col = 0; col < 3; col++) {
    int y = 0x50;
    for (int i = 0; i < 3; i++) {
      newsStory* story = &g_pNewsMgr->stories[pageNation][col][i];
      if (story->entry.storyId == 0) {
        continue;
      }
      FormatInterNationEventRowTokensToSharedStrings(story, tokens);
      if (story->feature38 != 0) {
        y += AppendInterNationEventSummaryTextEntry(col, y, story->entry.headlineTextOffset,
                                                    story->entry.headlineTextLength, &plainStyle, 1,
                                                    tokens);
      } else {
        y += AppendInterNationEventSummaryTextEntry(col, y, story->entry.headlineTextOffset,
                                                    story->entry.headlineTextLength, &featureStyle,
                                                    1, tokens);
      }
      y += AppendInterNationEventSummaryTextEntry(col, y, story->entry.storyTextOffset,
                                                  story->entry.storyTextLength, &titleStyle, -2,
                                                  tokens);
    }
  }
  g_pUiViewManager->ReleaseResourceStreamIfNotNull(newsTexStream94);
}

// FUNCTION: IMPERIALISM 0x0055d910
void TNewspaperView::FormatInterNationEventRowTokensToSharedStrings(newsStory* story,
                                                                    CString* tokens) {
  for (int k = 0; k < 4; k++) {
    int kind = story->parmKind[k];
    switch (kind) {
    case 1:
      BuildLocalizedTokenListFromBitmaskWithConjunction(&tokens[k], story->parmValue[k]);
      break;
    case 2:
      BuildLocalizedNationListFromBitmaskWithConjunction(&tokens[k], story->parmValue[k]);
      break;
    case 3: {
      CString cityName;
      g_pGlobalMapState->AssignCityRecordDisplayName(story->parmValue[k], &cityName);
      tokens[k] = cityName;
      break;
    }
    case 4: {
      TZone* actionContext = FindMapActionContextByNodeId(static_cast<short>(story->parmValue[k]));
      actionContext->AssignZoneDisplayNameToOutputRef(&tokens[k]);
      break;
    }
    default: {
      CString empty(g_szEmptyString);
      tokens[k] = empty;
      break;
    }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0055da80
void TNewspaperView::BuildLocalizedTokenListFromBitmaskWithConjunction(CString* out, int bitmask) {
  CString itemText;
  int emitted = 0;
  *out = CString(g_szEmptyString);
  char flags[0x17];
  int setCount = 0;
  for (int c = 0; c < 0x17; c++) {
    if (bitmask & (1 << c)) {
      flags[c] = 1;
      setCount++;
    } else {
      flags[c] = 0;
    }
  }
  for (int i = 0; i < 0x17; i++) {
    if (flags[i] == 0) {
      continue;
    }
    if (emitted == 0) {
      itemText = g_pSimMgr->AssignSharedStringFromIndexedSlot7C(i);
    } else {
      itemText = g_pSimMgr->LoadNormalizedCredentialName(i);
    }
    if (emitted == setCount - 2) {
      CString conjunctionText;
      g_pSimMgr->GetString(0x275e, 4, &conjunctionText);
      *out += itemText + conjunctionText;
    } else if (emitted == setCount - 1) {
      *out += itemText;
    } else {
      *out += itemText + g_szListSeparator_00695760;
    }
    emitted++;
  }
}

// FUNCTION: IMPERIALISM 0x0055dcd0
void TNewspaperView::BuildLocalizedNationListFromBitmaskWithConjunction(CString* out, int bitmask) {
  CString itemText;
  int emitted = 0;
  *out = CString(g_szEmptyString);
  char flags[0x17];
  int setCount = 0;
  for (int c = 0; c < 0x17; c++) {
    if (bitmask & (1 << c)) {
      flags[c] = 1;
      setCount++;
    } else {
      flags[c] = 0;
    }
  }
  for (int i = 0; i < 0x17; i++) {
    if (flags[i] == 0) {
      continue;
    }
    g_pSimMgr->GetString(0x2711, i, &itemText);
    if (emitted == setCount - 2) {
      *out += itemText + g_szListConjunction_00698498;
    } else if (emitted == setCount - 1) {
      *out += itemText;
    } else {
      *out += itemText + g_szListSeparator_00695760;
    }
    emitted++;
  }
}

// FUNCTION: IMPERIALISM 0x0055de90
void TNewspaperView::ProvinceParmList(CString& out, int cityRecordIndex) {
  CString cityName;
  g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
  out = cityName;
}

// FUNCTION: IMPERIALISM 0x0055df50
int TNewspaperView::AppendInterNationEventSummaryTextEntry(int column, int y, int recordOffset,
                                                           int recordLength, TextStyle* style,
                                                           int styleWord, CString* tokens) {
  TDeluxeText* text;
  int offsetPair[2];
  int sizePair[2];
  {
    int columnX[3];
    columnX[0] = 0x18;
    columnX[1] = 0xe2;
    columnX[2] = 0x1ac;
    text = new TDeluxeText();
    offsetPair[0] = columnX[column];
  }
  offsetPair[1] = y;
  {
    RECT inset;
    inset.left = 4;
    inset.top = 4;
    inset.right = 4;
    inset.bottom = 4;
    sizePair[0] = 0xbc;
    sizePair[1] = 0x18c;
    text->IDeluxeText(this, offsetPair, sizePair, &inset, style, static_cast<short>(styleWord));
  }

  char* recordBuffer = new char[recordLength];
  g_pUiViewManager->SeekResourceStreamFromBeginning(newsTexStream94, recordOffset);
  g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(newsTexStream94, recordBuffer,
                                                           &recordLength);
  char* formatted = AppendInterNationEventSummaryTextEntry_Impl(
      g_pSimMgr, recordBuffer, static_cast<LPCSTR>(tokens[0]), static_cast<LPCSTR>(tokens[1]),
      static_cast<LPCSTR>(tokens[2]), static_cast<LPCSTR>(tokens[3]));
  delete[] recordBuffer;

  const char* scan = formatted;
  while (*scan != 0) {
    scan++;
  }
  int formattedLength = static_cast<int>(scan - formatted) + 1;
  (void)formattedLength;

  CString textEntry(formatted);
  text->UpdateTextEntrySharedString(&textEntry);
  free(formatted);

  int consumedHeight = text->MeasureCurrentTextHeightInLayoutRect() + 8;
  CRect bounds;
  text->QueryBounds(&bounds);
  bounds.bottom = consumedHeight + bounds.top;
  text->ApplyBounds(&bounds, 0);
  return consumedHeight;
}
