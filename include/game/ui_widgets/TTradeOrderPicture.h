#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00664010
class TTradeOrderPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TTradeOrderPicture)
  virtual ~TTradeOrderPicture() override;      // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x584500
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x584520

  TTradeOrderPicture();
};
