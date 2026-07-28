#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e2f8
class TTradeOfferNationView : public TView {
public:
  DECLARE_DYNCREATE(TTradeOfferNationView)
  virtual ~TTradeOfferNationView() override;    // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5bd2d0

  // NOOP: verified empty in original 0x005bd223 (no standalone TTradeOfferNationView::TTradeOfferNationView body exists: CreateObject 0x005bd1f0 inlines this default ctor, calling the TView base ctor directly at that site)
  TTradeOfferNationView() {}

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended
  // at 0x60. The trailing 4 bytes split into two shorts, both read by Draw:
  // +0x60 indexes g_pNationInteractionStateManager->categoryRows[] and is the item arg to
  // GetBidderList; +0x62 indexes tradeOfferCells[] and is this row's nation slot.
  short categorySlot;
  short nationSlot;
};
ASSERT_SIZE(TTradeOfferNationView, 0x64);
