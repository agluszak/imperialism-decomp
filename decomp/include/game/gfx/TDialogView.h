#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064be28
class TDialogView : public TView {
public:
  DECLARE_DYNCREATE(TDialogView)
  virtual ~TDialogView() override;            // slot 0x01 (scalar deleting destructor)
  virtual void EnsureStylePayload() override; // slot 0x42 0x49d880

  // NOOP: verified empty in original 0x0049d725
  TDialogView() {}
};
ASSERT_SIZE(TDialogView, 0x60);
