#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064be28
class TDialogView : public TView {
public:
  DECLARE_DYNCREATE(TDialogView)
  virtual ~TDialogView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void EnsureField48Buffer() override; // slot 0x42 0x49d880

  TDialogView();
};
