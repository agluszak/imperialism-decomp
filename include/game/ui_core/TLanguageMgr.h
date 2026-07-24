#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006585a8
class TLanguageMgr : public TObject {
public:
  DECLARE_DYNCREATE(TLanguageMgr)
  virtual ~TLanguageMgr() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;     // slot 0x07 0x507e20
  unsigned char firstColumn;
  unsigned char padding05[3];
  int columnCount;
  unsigned char firstPrimaryRow;
  unsigned char padding0d[3];
  int primaryRowCount;
  unsigned char firstExtraRow;
  unsigned char padding15[3];
  int extraRowCount;
  char*** rowTextTable;
  unsigned int rowFlags;
  unsigned char groupCode;
  unsigned char delimiter;
  unsigned char padding26[2];
  CString newsTexPath;
  CString newsTabPath;

  // Header-inline accessors in the original whose COMDAT copies landed in the
  // UNewspaper TU (0x55ba10/0x55bbf0); the news phase calls them on g_pLanguageMgr.
  CString& GetNewsTexPath();
  CString& GetNewsTabPath();
  int field30;

  TLanguageMgr();
  bool LoadNewsTabTexResourcesAndBuildEntries(const char* basePath, int languageTag);
  void FreeNestedPointerTableRowsAndResetDimensions();
  void BuildNewsTableDimensions(char firstColumn, char lastColumn, char firstPrimaryRow,
                                char lastPrimaryRow, char firstExtraRow, char lastExtraRow);
  void ParseNewsTableRow(char* line);
  // Mac CodeWarrior oracle: TLanguageMgr::Localize(const char*, unsigned char) const.
  // Maps a data byte through the news-string table for the requested format column,
  // expanding '*' in the mapped fragment to the raw data string. 0x005083f0.
  CString Localize(const char* data, unsigned char formatChar) const;
  char PickGender(const char* name) const; // 0x00508910
  // 0x508c50: normalize a player-name credential token (returns the CString by value —
  // ret 8 with a hidden return slot). Names starting with '(' or an uppercase letter
  // pass through; otherwise the first character is stripped when the news table is
  // loaded or the name starts with a space. Turn-event-9 lounge name-label path.
  CString NormalizeRuntimeCredentialNameToken(CString* name);
  bool ReloadPreplutNewsTableAndResources(int languageTag);
};
ASSERT_SIZE(TLanguageMgr, 0x34);
