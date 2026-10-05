#pragma once

#include "compat.h"

#include "game/ui_screens/TNewsMgr.h" // newsStory rows rendered by the advisor summary
#include "game/ui_tags_screens.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641390
class TNewspaperView : public TPicture {
public:
  DECLARE_DYNCREATE(TNewspaperView)
  virtual ~TNewspaperView() override; // slot 0x01 (scalar deleting destructor)

  int summaryPageIndex; // 0x90
  CFile* newsTexStream; // 0x94

  TNewspaperView();

  void StuffValues(int pageIndex);
  // 0x55d910: fill tokens[0..3] from the story's {parmValue, parmKind} pairs.
  void CreateVariables(newsStory* story, CString* tokens);
  // 0x55da80: comma/"and" list of commodity names for the set bits (bit 0..0x16).
  void BuildLocalizedTokenListFromBitmaskWithConjunction(CString* out, int bitmask);
  // 0x55dcd0: same shape over nation names (string group 0x2711).
  void BuildLocalizedNationListFromBitmaskWithConjunction(CString* out, int bitmask);
  void ProvinceParmList(CString& out, int cityRecordIndex);
  int AppendInterNationEventSummaryTextEntry(int column, int y, int recordOffset, int recordLength,
                                             TextStyle* style, int styleWord, CString* tokens);
};
ASSERT_SIZE(TNewspaperView, 0x98);
