#pragma once

#include "game/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640f58
class TTradePageSellView : public TPageView {
public:
  DECLARE_DYNCREATE(TTradePageSellView)
  virtual ~TTradePageSellView() override; // slot 0x01 (scalar deleting destructor)

  // Cache of the last-built category slot; RebuildNationOfferRowsForCategory no-ops if
  // asked to rebuild for the same category again.
  short lastBuiltCategorySlot84; // 0x84

  TTradePageSellView();
  // 0x5bcc30 -- rebuilds orderedEntries for categorySlot: clears the existing
  // rows (slot 0x6d), then either one TTradeOfferNationLine row per nation whose
  // TTradeMgr cell is negative/positive for (nation, categorySlot), or a single
  // fallback row when categorySlot is -1 or no nation qualifies.
  void RebuildNationOfferRowsForCategory(short categorySlot);
};
