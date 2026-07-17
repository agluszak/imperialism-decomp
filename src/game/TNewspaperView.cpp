#include "game/TNewspaperView.h"

#include "game/CFile_Virtuals.h"
#include "game/TAssetMgr.h"
#include "game/TDeluxeText.h"
#include "game/TLanguageMgr.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"

#include <string.h>

// SYNTHETIC: IMPERIALISM 0x00435710
// TNewspaperView::`scalar deleting destructor'
TNewspaperView::~TNewspaperView() {}
// SYNTHETIC: IMPERIALISM 0x0055d160
// TNewspaperView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0055d1e0
// TNewspaperView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNewspaperView, TPicture)

TNewspaperView::TNewspaperView() {}

// FUNCTION: IMPERIALISM 0x0055d910
void TNewspaperView::FormatInterNationEventRowTokensToSharedStrings(int* entry, CString* tokens) {
  for (int k = 0; k < 4; k++) {
    int type = entry[k + 4];
    switch (type) {
    case 1:
      BuildLocalizedTokenListFromBitmaskWithConjunction(&tokens[k], entry[k]);
      break;
    case 2:
      BuildLocalizedNationListFromBitmaskWithConjunction(&tokens[k], entry[k]);
      break;
    case 3: {
      CString cityName;
      g_pGlobalMapState->AssignCityRecordDisplayName(entry[k], &cityName);
      tokens[k] = cityName;
      break;
    }
    case 4: {
      TZone* actionContext = FindMapActionContextByNodeId(static_cast<short>(entry[k]));
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

// FUNCTION: IMPERIALISM 0x0055df50
int TNewspaperView::AppendInterNationEventSummaryTextEntry(int column, int y, int recordId,
                                                           int recordLength,
                                                           TControlPictureRectState* style,
                                                           int styleWord, CString* tokens) {
  (void)recordId;
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
    text->ConstructTDeluxeTextBaseState(this, offsetPair, sizePair, &inset, style,
                                        static_cast<short>(styleWord));
  }

  char* recordBuffer = new char[recordLength];
  g_pUiViewManager->InvokeVtableSlot30OnTargetObject(newsTexStream94, recordLength);
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

  int consumedHeight = text->MeasureCurrentTextWidthInLayoutRect() + 8;
  RECT bounds;
  text->QueryBounds(&bounds);
  bounds.bottom = consumedHeight + bounds.top;
  text->ApplyBounds(&bounds, 0);
  return consumedHeight;
}
