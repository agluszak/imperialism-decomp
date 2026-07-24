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

  // NOOP: verified empty in original 0x005b2773 (no standalone TGameSetupDialog::TGameSetupDialog body exists: CreateObject 0x005b2740 inlines this default ctor, calling the TView base ctor directly at that site)
  TGameSetupDialog() {}
};
ASSERT_SIZE(TGameSetupDialog, 0x60);
