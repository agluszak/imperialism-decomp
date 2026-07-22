#pragma once

#include "game/TNewsMgr.h" // newsStory rows rendered by the advisor summary
#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641390
class TNewspaperView : public TPicture {
public:
  DECLARE_DYNCREATE(TNewspaperView)
  virtual ~TNewspaperView() override; // slot 0x01 (scalar deleting destructor)

  // Layout past TPicture (0x90): the advisor-summary builder caches its page argument
  // and holds the news .tex resource stream open across the row loop.
  int summaryPageIndex90;                // 0x90
  class CFile_Virtuals* newsTexStream94; // 0x94

  TNewspaperView();

  // 0x55d200: populate the nation-status advisor page — 'date'/'spec' children plus
  // the 3x3 inter-nation event row grid from g_pNewsMgr.
  void BuildInterNationEventSummaryRowsForAdvisorDialog(int pageIndex);
  // 0x55d910: fill tokens[0..3] from the story's {parmValue, parmKind} pairs.
  void FormatInterNationEventRowTokensToSharedStrings(newsStory* story, CString* tokens);
  // 0x55da80: comma/"and" list of commodity names for the set bits (bit 0..0x16).
  void BuildLocalizedTokenListFromBitmaskWithConjunction(CString* out, int bitmask);
  // 0x55dcd0: same shape over nation names (string group 0x2711).
  void BuildLocalizedNationListFromBitmaskWithConjunction(CString* out, int bitmask);
  // Mac oracle: ProvinceParmList(CStr255&, long). Resolve a province/city record index
  // through the global map's localized display-name table.
  void ProvinceParmList(CString& out, int cityRecordIndex);
  // 0x55df50: build one TDeluxeText row (column grid x=0x18/0xe2/0x1ac) from the .tex
  // record, expand its bracket template with tokens, and return the consumed height.
  int AppendInterNationEventSummaryTextEntry(int column, int y, int recordId, int recordLength,
                                             TextStyle* style, int styleWord, CString* tokens);
};
