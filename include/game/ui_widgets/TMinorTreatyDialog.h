#pragma once

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bf80
class TMinorTreatyDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TMinorTreatyDialog)
  virtual ~TMinorTreatyDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues();             // slot 0x68 0x5b4090

  TMinorTreatyDialog();
};
