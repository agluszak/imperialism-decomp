#pragma once

#include "compat.h"

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640f58
class TTradePageSellView : public TPageView {
public:
  DECLARE_DYNCREATE(TTradePageSellView)
  virtual ~TTradePageSellView() override; // slot 0x01 (scalar deleting destructor)

  short lastBuiltCategorySlot; // 0x84

  TTradePageSellView();
  void SetItem(short categorySlot);
};
ASSERT_SIZE(TTradePageSellView, 0x88);
