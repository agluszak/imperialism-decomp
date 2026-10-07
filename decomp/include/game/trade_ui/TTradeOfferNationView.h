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

  // NOOP: verified empty in original 0x005bd223
  TTradeOfferNationView() {}

  short categorySlot;
  short nationSlot;

  void ITradeOfferNationView(TView* panel, int* offsetLayout, int* sizeLayout, short nation,
                             short category);
};
ASSERT_SIZE(TTradeOfferNationView, 0x64);
