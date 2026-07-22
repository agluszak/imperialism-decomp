#pragma once

#include "game/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b7a0
class TMinorTradeBidsDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorTradeBidsDialog)
  virtual ~TMinorTradeBidsDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues();                // slot 0x68 0x5b2aa0

  TMinorTradeBidsDialog();
};
