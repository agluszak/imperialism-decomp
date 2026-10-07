#pragma once

#include "compat.h"

#include "game/ui_screens/TPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00640d48
class TTradePageBuyView : public TPageView {
public:
  DECLARE_DYNCREATE(TTradePageBuyView)
  virtual ~TTradePageBuyView() override;

  short lastBuiltCategorySlot;

  TTradePageBuyView();
  void SetItem(short categorySlot);
};
ASSERT_SIZE(TTradePageBuyView, 0x88);
