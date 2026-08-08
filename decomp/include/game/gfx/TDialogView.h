#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064be28
class TDialogView : public TView {
public:
  DECLARE_DYNCREATE(TDialogView)
  virtual ~TDialogView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void EnsureField48Buffer() override; // slot 0x42 0x49d880

  // In-class inline: the original has no out-of-line TDialogView::TDialogView -- every
  // caller absorbs it, so an out-of-line definition pessimizes them into a call.
  // NOOP: verified empty in original 0x0049d725 (no standalone TDialogView::TDialogView body exists: CreateObject 0x0049d6f0 inlines this default ctor, calling the TView base ctor directly at that site)
  TDialogView() {}
};
ASSERT_SIZE(TDialogView, 0x60);
