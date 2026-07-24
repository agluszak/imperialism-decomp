#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b7a0
class TMinorTradeBidsDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorTradeBidsDialog)
  virtual ~TMinorTradeBidsDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues();                // slot 0x68 0x5b2aa0

  // NOOP: verified empty in original 0x005b29d3 (no standalone TMinorTradeBidsDialog::TMinorTradeBidsDialog body exists: CreateObject 0x005b29a0 inlines this default ctor, calling the TView base ctor directly at that site)
  TMinorTradeBidsDialog() {}
};
ASSERT_SIZE(TMinorTradeBidsDialog, 0x60);
