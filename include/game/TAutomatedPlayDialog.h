#pragma once

#include "game/TDialogView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066c178
class TAutomatedPlayDialog : public TDialogView {
public:
  DECLARE_DYNCREATE(TAutomatedPlayDialog)
  virtual ~TAutomatedPlayDialog() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;            // slot 0x28 0x5b46c0

  TAutomatedPlayDialog();
};
