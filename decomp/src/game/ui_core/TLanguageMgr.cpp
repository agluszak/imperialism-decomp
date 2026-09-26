#include "game/ui_core/TLanguageMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"

#include "game/ImperialismApp.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_screens/TRadioText.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

namespace {
const char kNewsTexPath[] = "news.tex";
const char kNewsTabPath[] = "news.tab";
const char kPreplutPath[] = "preplut.";
const char kReadTextMode[] = "rt";
} // namespace

// SYNTHETIC: IMPERIALISM 0x00507bc0
// TLanguageMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00507c40
// TLanguageMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLanguageMgr, TObject)

// FUNCTION: IMPERIALISM 0x00507c60
TLanguageMgr::TLanguageMgr() : TObject() {
  columnCount = 0;
  primaryRowCount = 0;
  rowTextTable = 0;
  rowFlags = 0;
  groupCode = 0;
  newsTexPath = kNewsTexPath;
  newsTabPath = kNewsTabPath;
  delimiter = 0x20;
  field30 = 6;
}

// SYNTHETIC: IMPERIALISM 0x00507d80
// TLanguageMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00507db0
TLanguageMgr::~TLanguageMgr() {}

// FUNCTION: IMPERIALISM 0x00507e20
void TLanguageMgr::Free() {
  FreeTableRows();
  delete this;
}

// FUNCTION: IMPERIALISM 0x00507e50
bool TLanguageMgr::ReadPrepLUT(const char* basePath, unsigned long languageTag) {
  (void)languageTag;
  CString tablePath(GetDataDirectoryPathLiteral());
  tablePath += basePath;
  newsTabPath = kNewsTabPath;
  newsTexPath = kNewsTexPath;
  delimiter = 0x20;
  FreeTableRows();

  FILE* stream = fopen(tablePath, kReadTextMode);
  if (stream == 0) {
    return false;
  }

  char line[0x100];
  while (fgets(line, 0xff, stream) != 0) {
    char* entry = line;
    if (line[0] == '>') {
      entry = line + 1;
    }

    const char marker = *entry;
    if (marker == '#') {
      break;
    }

    if (marker == '%') {
      switch (entry[1]) {
      case 'G':
        groupCode = entry[2];
        break;
      case 'N': {
        char* resourceName = entry + 4;
        for (char* cursor = resourceName; *cursor != '\0'; ++cursor) {
          if (*cursor == '\r' || *cursor == '\n') {
            *cursor = '\0';
          }
        }
        if (entry[2] == 'X') {
          newsTexPath = resourceName;
        }
        if (entry[2] == 'B') {
          newsTabPath = resourceName;
        }
        break;
      }
      case 'R':
        field30 = atoi(entry + 2);
        break;
      case '[': {
        char firstExtra = 1;
        char lastExtra = 0;
        if (entry[9] == ',') {
          firstExtra = entry[10];
          lastExtra = entry[12];
        }
        AllocateTable(entry[2], entry[4], entry[6], entry[8], firstExtra, lastExtra);
        break;
      }
      }
    } else if (marker == '.') {
      ParseRow(entry);
    }
  }

  fclose(stream);
  return true;
}

// FUNCTION: IMPERIALISM 0x00508280
int IsNewsTableColumnDelimiter(char value) {
  return value == '\n' || value == '\r' || value == '\t' || value == '\0';
}

// FUNCTION: IMPERIALISM 0x005082b0
void TLanguageMgr::ParseRow(const char* line) {
  // Retail sign-extends the row code before choosing the primary or extra range.
  int rowIndex = line[1];
  if (rowIndex < firstPrimaryRow || rowIndex >= firstPrimaryRow + primaryRowCount) {
    rowIndex += primaryRowCount - firstExtraRow;
  } else {
    rowIndex -= firstPrimaryRow;
  }

  const char* text = line + 2;
  if (*text == '_') {
    ++text;
    rowFlags |= 1u << (rowIndex & 0x1f);
    delimiter = line[1];
  }

  for (int column = 0; column < columnCount; ++column) {
    while (IsNewsTableColumnDelimiter(*text)) {
      ++text;
    }
    const char* end = text;
    while (!IsNewsTableColumnDelimiter(*end)) {
      ++end;
    }
    const int length = static_cast<int>(end - text);
    rowTextTable[rowIndex][column] = new char[length + 1];
    memcpy(rowTextTable[rowIndex][column], text, length);
    rowTextTable[rowIndex][column][length] = '\0';
    text = end;
  }
}

// FUNCTION: IMPERIALISM 0x005083f0
CString TLanguageMgr::Localize(const char* data, unsigned char formatChar) const {
  if (formatChar == '\0') {
    return CString(data);
  }

  CString result;
  const unsigned char dataCode = static_cast<unsigned char>(*data);
  const bool columnInRange = formatChar >= firstColumn && formatChar - firstColumn < columnCount;
  const bool primaryRowInRange =
      dataCode >= firstPrimaryRow && dataCode - firstPrimaryRow < primaryRowCount;
  const bool extraRowInRange =
      dataCode >= firstExtraRow && dataCode - firstExtraRow < extraRowCount;

  if (!columnInRange || (!primaryRowInRange && !extraRowInRange)) {
    // Invalid codes pass through, except that an initial space is removed.
    result = CString(*data == ' ' ? data + 1 : data);
    return result;
  }

  const int row =
      primaryRowInRange ? dataCode - firstPrimaryRow : primaryRowCount + dataCode - firstExtraRow;
  const char* fragment = rowTextTable[static_cast<unsigned char>(row)][formatChar - firstColumn];
  for (; *fragment != '\0'; ++fragment) {
    if (*fragment == '*') {
      result += data + 1;
    } else {
      result += *fragment;
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005086a0
bool TLanguageMgr::SetLanguage(unsigned long languageTag) {
  FreeTableRows();

  CString preplutPath(kPreplutPath);
  if (g_pImperialismApp != nullptr) {
    preplutPath += g_pImperialismApp->languageCodeStringE0;
  }
  return ReadPrepLUT(preplutPath, languageTag);
}

// FUNCTION: IMPERIALISM 0x00508760
void TLanguageMgr::FreeTableRows() {
  if (rowTextTable == 0) {
    return;
  }

  const int rowCount = primaryRowCount + extraRowCount;
  for (int row = 0; row < rowCount; ++row) {
    if (rowTextTable[row] != 0) {
      for (int column = 0; column < columnCount; ++column) {
        delete[] rowTextTable[row][column];
      }
      delete[] rowTextTable[row];
    }
  }

  delete[] rowTextTable;
  extraRowCount = 0;
  primaryRowCount = 0;
  columnCount = 0;
  rowTextTable = 0;
}

// FUNCTION: IMPERIALISM 0x00508800
void TLanguageMgr::AllocateTable(unsigned char firstColumnArg, unsigned char lastColumn,
                                 unsigned char firstPrimaryRowArg, unsigned char lastPrimaryRow,
                                 unsigned char firstExtraRowArg, unsigned char lastExtraRow) {
  FreeTableRows();
  firstColumn = firstColumnArg;
  firstPrimaryRow = firstPrimaryRowArg;
  firstExtraRow = firstExtraRowArg;
  columnCount = lastColumn - firstColumn + 1;
  primaryRowCount = lastPrimaryRow - firstPrimaryRow + 1;
  extraRowCount = lastExtraRow - firstExtraRow + 1;

  const int rowCount = primaryRowCount + extraRowCount;
  rowTextTable = new char**[rowCount];
  for (int row = 0; row < rowCount; ++row) {
    rowTextTable[row] = new char*[columnCount];
    for (int column = 0; column < columnCount; ++column) {
      rowTextTable[row][column] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00508910
char TLanguageMgr::PickGender(const char* name) const {
  CString questionText;
  if (groupCode == 0) {
    return delimiter;
  }

  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventVerbFormDialog));
  g_pSimMgr->GetString(0x2737, 0x34, &questionText);
  TStaticText* question = static_cast<TStaticText*>(dialog->ResolveControlByTag(kControlTagQues));
  ApplyControlThemeStyleAndOptionalCaption(question, 0, 0xc, 0x2b6b, 1, questionText);

  TRadioTextCluster* form =
      static_cast<TRadioTextCluster*>(dialog->ResolveControlByTag(kControlTagForm));
  form->AssertValid();
  form->frameThemeCode90 = 0x2b6b;
  form->itemInset92 = 2;

  unsigned long firstTag = 0;
  int rowCount = primaryRowCount + extraRowCount;
  for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex) {
    if ((rowFlags & (1u << (rowIndex & 0x1f))) != 0) {
      int rowOffset;
      if (rowIndex < primaryRowCount) {
        rowOffset = static_cast<unsigned char>(firstPrimaryRow);
      } else {
        rowOffset = static_cast<unsigned char>(firstExtraRow) - primaryRowCount;
      }

      CString codedName;
      codedName += static_cast<char>(rowIndex + rowOffset);
      codedName += name;
      CString localizedName = Localize(codedName, groupCode);
      unsigned long itemTag = kControlTagFrm0 + rowIndex;
      TRadioText* item = form->AddItem(itemTag, rowIndex, localizedName, 0xf, -1);
      ApplyUiTextStyleAndThemeFlags(item, 0, 0xc, 0x2b6b, 0x2b6c);
      item->SetTextAlignmentAndMaybeRefresh(1, 0);
      if (firstTag == 0) {
        firstTag = itemTag;
      }
    }
  }

  form->SetSelectedTextOptionByTag(firstTag, false);
  dialog->SetModality(1);
  TDialogBehavior* behavior = dialog->GetDialogBehavior();
  if (behavior != 0) {
    behavior->defaultCommandCode = kControlTagOkay;
  }
  dialog->PoseModally();

  unsigned char selectedIndex = static_cast<unsigned char>(form->selectedTag88) - '0';
  char rowBase = selectedIndex < primaryRowCount ? firstPrimaryRow : firstExtraRow;
  dialog->Close();
  dialog->Free();
  return static_cast<char>(selectedIndex + rowBase);
}

// FUNCTION: IMPERIALISM 0x00508c50
CString TLanguageMgr::StripCodeStr(const CString& name) const {
  CString token;
  const char* text = name;
  char first = *text;
  if (first == '(' || (first >= 'A' && first <= 'Z')) {
    token = CString(text);
  } else {
    if (rowTextTable != 0 || first == ' ') {
      token = CString(text + 1);
    } else {
      token = CString(text);
    }
  }
  return token;
}

// FUNCTION: IMPERIALISM 0x0055ba10
CString& TLanguageMgr::GetNewsTexPath() {
  return newsTexPath;
}

// FUNCTION: IMPERIALISM 0x0055bbf0
CString& TLanguageMgr::GetNewsTabPath() {
  return newsTabPath;
}
