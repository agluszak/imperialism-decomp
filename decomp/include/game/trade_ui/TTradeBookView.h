#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TTradePageBuyView;
class TTradePageSellView;

class TControl;

// VTABLE: IMPERIALISM 0x00640b50
class TTradeBookView : public TView {
public:
  DECLARE_DYNCREATE(TTradeBookView)
  virtual ~TTradeBookView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x005bde65
  TTradeBookView() {}

  TControl* previousPageButton;  // tag 'lcor'
  TControl* nextPageButton;      // tag 'rcor'
  TTradePageBuyView* buyPanel;   // tag 'tbou'
  TTradePageSellView* sellPanel; // tag 'tsol'
  int pageCount;
  int currentPage;

  void SetItem(short categorySlot);

  void ShowPage(int page);
};
ASSERT_SIZE(TTradeBookView, 0x78);
