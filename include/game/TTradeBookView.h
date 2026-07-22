#pragma once

#include "game/TView.h"
#include "game/mfc.h"

class TTradePageBuyView;
class TTradePageSellView;

class TControl;

// VTABLE: IMPERIALISM 0x00640b50
class TTradeBookView : public TView {
public:
  DECLARE_DYNCREATE(TTradeBookView)
  virtual ~TTradeBookView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005be370
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5bdef0

  TTradeBookView();

  TControl* previousPageButton;  // 0x60, tag 'lcor'
  TControl* nextPageButton;      // 0x64, tag 'rcor'
  TTradePageBuyView* buyPanel;   // 0x68, tag 'tbou'
  TTradePageSellView* sellPanel; // 0x6c, tag 'tsol'
  int pageCount;                 // 0x70
  int currentPage;               // 0x74

  // Mac name oracle: TTradeBookView::ShowPage(long).
  void ShowPage(int page); // 0x5be3e0
};
