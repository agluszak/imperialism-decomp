#pragma once

#include "compat.h"

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640d48
class TTradePageBuyView : public TPageView {
public:
  DECLARE_DYNCREATE(TTradePageBuyView)
  virtual ~TTradePageBuyView() override; // slot 0x01 (scalar deleting destructor)

  // Cache of the last-built category slot; RebuildNationBidRowsForCategory no-ops if
  // asked to rebuild for the same category again.
  short lastBuiltCategorySlot84; // 0x84

  TTradePageBuyView();
  // 0x5bd690 -- mirrors TTradePageSellView::RebuildNationOfferRowsForCategory but with
  // an ascending nation loop (0..0x16), a single header-row style variant, and no
  // fallback row: on categorySlot == -1 or no qualifying nation, the row list is simply
  // left cleared.
  void RebuildNationBidRowsForCategory(short categorySlot);
};
ASSERT_SIZE(TTradePageBuyView, 0x88);
