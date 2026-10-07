#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b7a0
class TMinorTradeBidsDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorTradeBidsDialog)
  virtual ~TMinorTradeBidsDialog() override;
  virtual void StuffValues();

  // NOOP: verified empty in original 0x005b29d3
  TMinorTradeBidsDialog() {}
};
ASSERT_SIZE(TMinorTradeBidsDialog, 0x60);
