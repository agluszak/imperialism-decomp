#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066b380
class TGameSetupDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TGameSetupDialog)
  ~TGameSetupDialog() override;

  virtual void StuffValues();

  // NOOP: verified empty in original 0x005b2773
  TGameSetupDialog() {}
};
ASSERT_SIZE(TGameSetupDialog, 0x60);
