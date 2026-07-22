#include "game/TLanguageMgr.h"

#include "game/ImperialismApp.h"
#include "game/TAssetMgr.h"
#include "game/TRadioText.h"
#include "game/TRadioTextCluster.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
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

TLanguageMgr::~TLanguageMgr() {}

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

// FUNCTION: IMPERIALISM 0x00507e20
void TLanguageMgr::Free() {
  FreeNestedPointerTableRowsAndResetDimensions();
  delete this;
}

// FUNCTION: IMPERIALISM 0x00507e50
bool TLanguageMgr::LoadNewsTabTexResourcesAndBuildEntries(const char* basePath, int languageTag) {
  (void)languageTag;
  CString tablePath(GetDataDirectoryPathLiteral());
  tablePath += basePath;
  newsTabPath = kNewsTabPath;
  newsTexPath = kNewsTexPath;
  delimiter = 0x20;
  FreeNestedPointerTableRowsAndResetDimensions();

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
        BuildNewsTableDimensions(entry[2], entry[4], entry[6], entry[8], firstExtra, lastExtra);
        break;
      }
      }
    } else if (marker == '.') {
      ParseNewsTableRow(entry);
    }
  }

  fclose(stream);
  return true;
}

// FUNCTION: IMPERIALISM 0x005082b0
void TLanguageMgr::ParseNewsTableRow(char* line) {
  int rowIndex = static_cast<unsigned char>(line[1]);
  if (rowIndex < firstPrimaryRow || rowIndex >= firstPrimaryRow + primaryRowCount) {
    rowIndex += primaryRowCount - firstExtraRow;
  } else {
    rowIndex -= firstPrimaryRow;
  }

  char* text = line + 2;
  if (*text == '_') {
    ++text;
    rowFlags |= 1u << (rowIndex & 0x1f);
    delimiter = line[1];
  }

  for (int column = 0; column < columnCount; ++column) {
    while (*text == '\n' || *text == '\r' || *text == '\t' || *text == '\0') {
      ++text;
    }
    char* end = text;
    while (*end != '\n' && *end != '\r' && *end != '\t' && *end != '\0') {
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
  unsigned char dataByte = static_cast<unsigned char>(*data);
  CString result;
  unsigned char column = static_cast<unsigned char>(firstColumn);
  if (formatChar < column ||
      columnCount <= static_cast<int>(static_cast<unsigned int>(formatChar) - column) ||
      ((dataByte < static_cast<unsigned char>(firstPrimaryRow) ||
        primaryRowCount <= static_cast<int>(dataByte - firstPrimaryRow)) &&
       (dataByte < static_cast<unsigned char>(firstExtraRow) ||
        extraRowCount <= static_cast<int>(dataByte - firstExtraRow)))) {
    // Format column or data byte out of range: fall back to the raw string (dropping a
    // leading space if present).
    if (*data == ' ') {
      result = CString(data + 1);
    } else {
      result = CString(data);
    }
  } else {
    unsigned char mappedColumn = formatChar - column;
    char rowOffset;
    if (dataByte < static_cast<unsigned char>(firstPrimaryRow) ||
        primaryRowCount + firstPrimaryRow <= static_cast<int>(dataByte)) {
      rowOffset = static_cast<char>(primaryRowCount) - static_cast<char>(firstExtraRow);
    } else {
      rowOffset = -static_cast<char>(firstPrimaryRow);
    }
    char* fragment = rowTextTable[static_cast<unsigned char>(dataByte + rowOffset)][mappedColumn];
    for (char c = *fragment; c != '\0'; c = *fragment) {
      if (c == '*') {
        result += data + 1;
      } else {
        result += c;
      }
      fragment = fragment + 1;
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005086a0
bool TLanguageMgr::ReloadPreplutNewsTableAndResources(int languageTag) {
  FreeNestedPointerTableRowsAndResetDimensions();

  CString preplutPath(kPreplutPath);
  if (g_pImperialismApp != nullptr) {
    preplutPath += g_pImperialismApp->languageCodeStringE0;
  }
  return LoadNewsTabTexResourcesAndBuildEntries(preplutPath, languageTag);
}

// FUNCTION: IMPERIALISM 0x00508760
void TLanguageMgr::FreeNestedPointerTableRowsAndResetDimensions() {
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
void TLanguageMgr::BuildNewsTableDimensions(char firstColumnArg, char lastColumn,
                                            char firstPrimaryRowArg, char lastPrimaryRow,
                                            char firstExtraRowArg, char lastExtraRow) {
  FreeNestedPointerTableRowsAndResetDimensions();
  firstColumn = firstColumnArg;
  firstPrimaryRow = firstPrimaryRowArg;
  firstExtraRow = firstExtraRowArg;
  columnCount = static_cast<unsigned char>(lastColumn) - firstColumn + 1;
  primaryRowCount = static_cast<unsigned char>(lastPrimaryRow) - firstPrimaryRow + 1;
  extraRowCount = static_cast<unsigned char>(lastExtraRow) - firstExtraRow + 1;

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
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventVerbFormDialog));
  g_pSimMgr->GetString(0x2737, 0x34, &questionText);
  TStaticText* question = static_cast<TStaticText*>(dialog->ResolveControlByTag(0x71756573));
  ApplyControlThemeStyleAndOptionalCaption(question, 0, 0xc, 0x2b6b, 1, questionText);

  TRadioTextCluster* form =
      static_cast<TRadioTextCluster*>(dialog->ResolveControlByTag(0x666f726d));
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
      unsigned long itemTag = 0x66726d30 + rowIndex;
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
    behavior->defaultCommandCode = 0x6f6b6179;
  }
  dialog->PoseModally();

  unsigned char selectedIndex = static_cast<unsigned char>(form->selectedTag88) - '0';
  char rowBase = selectedIndex < primaryRowCount ? firstPrimaryRow : firstExtraRow;
  dialog->Close();
  dialog->Free();
  return static_cast<char>(selectedIndex + rowBase);
}

// FUNCTION: IMPERIALISM 0x00508c50
CString TLanguageMgr::NormalizeRuntimeCredentialNameToken(CString* name) {
  CString token;
  const char* text = *name;
  char first = *text;
  if (first == '(' || (first >= 'A' && first <= 'Z')) {
    token = CString(text);
  } else {
    unsigned char newsTableLoaded = (rowTextTable != 0);
    if (newsTableLoaded != 0 || first == ' ') {
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
