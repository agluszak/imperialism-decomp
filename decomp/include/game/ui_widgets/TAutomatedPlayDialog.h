#pragma once

#include "compat.h"

#include "game/gfx/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066c178
class TAutomatedPlayDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TAutomatedPlayDialog)
  virtual ~TAutomatedPlayDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;            // slot 0x28 0x5b46c0

  // NOOP: verified empty in original 0x005b45f3 (no standalone TAutomatedPlayDialog::TAutomatedPlayDialog body exists: CreateObject 0x005b45c0 inlines this default ctor, calling the TView base ctor directly at that site)
  TAutomatedPlayDialog() {}
};
ASSERT_SIZE(TAutomatedPlayDialog, 0x60);
