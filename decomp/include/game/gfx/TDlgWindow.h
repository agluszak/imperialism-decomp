#pragma once

#include "compat.h"
#include "game/ui_core/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656ce8
class TDlgWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TDlgWindow)
  virtual ~TDlgWindow() override;                       // slot 0x01 (scalar deleting destructor)
  virtual void Activate(unsigned char active) override; // slot 0x72 0x5003a0

  TDlgWindow();
};

ASSERT_SIZE(TDlgWindow, 0xa0);
