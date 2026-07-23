#pragma once

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066bd88
class TGPTreatyDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TGPTreatyDialog)
  virtual ~TGPTreatyDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void StuffValues();          // slot 0x68 0x5b3be0

  TGPTreatyDialog();
};
