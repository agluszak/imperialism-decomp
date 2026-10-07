#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006585a8
class TLanguageMgr : public TObject {
public:
  DECLARE_DYNCREATE(TLanguageMgr)
  virtual ~TLanguageMgr() override;
  virtual void Free() override;
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

  CString& GetNewsTexPath();
  CString& GetNewsTabPath();
  int flavorTextNationIndex;

  TLanguageMgr();
  bool ReadPrepLUT(const char* basePath, unsigned long languageTag);
  void FlushToilet();
  void Allocate(unsigned char firstColumn, unsigned char lastColumn, unsigned char firstPrimaryRow,
                unsigned char lastPrimaryRow, unsigned char firstExtraRow,
                unsigned char lastExtraRow);
  void ParseRow(const char* line);
  CString Localize(const char* data, unsigned char formatChar) const;
  char PickGender(const char* name) const;
  CString StripCodeStr(const CString& name) const;
  bool SetLanguage(unsigned long languageTag);
};
ASSERT_SIZE(TLanguageMgr, 0x34);
