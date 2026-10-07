#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00664010
class TTradeOrderPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTradeOrderPicture)
  virtual ~TTradeOrderPicture() override;
  virtual void DoPostCreate(int arg) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  TTradeOrderPicture();
#ifdef IMPERIALISM_RUNTIME_TESTS
  void ActivateOrderSemantically();
#endif
};
ASSERT_SIZE(TTradeOrderPicture, 0x90);
