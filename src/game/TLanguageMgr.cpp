#include "game/TLanguageMgr.h"

#include "game/ImperialismApp.h"
#include "game/global_data_tables.h"
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

namespace {
const char kNewsTexPath[] = "news.tex";
const char kNewsTabPath[] = "news.tab";
const char kPreplutPath[] = "preplut.";
const char kReadTextMode[] = "rt";
} // namespace

const char* LoadNewsTabTexResourcesAndBuildEntries_Impl_At00414850();

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
IMPLEMENT_DYNCREATE(TLanguageMgr, TObject)

TLanguageMgr::~TLanguageMgr() {}

void TLanguageMgr::Free() {}

// FUNCTION: IMPERIALISM 0x00507e50
bool TLanguageMgr::LoadNewsTabTexResourcesAndBuildEntries(const char* basePath, int languageTag) {
  (void)languageTag;
  CString tablePath(LoadNewsTabTexResourcesAndBuildEntries_Impl_At00414850());
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

// FUNCTION: IMPERIALISM 0x005086a0
bool TLanguageMgr::ReloadPreplutNewsTableAndResources(int languageTag) {
  FreeNestedPointerTableRowsAndResetDimensions();

  CString preplutPath(kPreplutPath);
  if (DAT_006a1348 != nullptr) {
    preplutPath += DAT_006a1348->field_E0;
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
