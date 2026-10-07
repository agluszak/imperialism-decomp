#pragma once

#include "compat.h"

#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641390
class TNewspaperView : public TPicture {
public:
  DECLARE_DYNCREATE(TNewspaperView)
  virtual ~TNewspaperView() override;

  int summaryPageIndex;
  CFile* newsTexStream;

  TNewspaperView();

  void StuffValues(int pageNation);
  void CreateVariables(newsStory* story, CString* tokens);
  void ItemParmList(CString* out, int bitmask);
  void CountryParmList(CString* out, int bitmask);
  void ProvinceParmList(CString& out, int cityRecordIndex);
  int AddTextView(int column, int y, int recordOffset, int recordLength, TextStyle* style,
                  int styleWord, CString* tokens);
};
ASSERT_SIZE(TNewspaperView, 0x98);
