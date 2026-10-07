#pragma once

#include "compat.h"
#include "game/ui_core/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656ce8
class TDlgWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TDlgWindow)
  virtual ~TDlgWindow() override;
  virtual void Activate(unsigned char active) override;

  TDlgWindow();
};

ASSERT_SIZE(TDlgWindow, 0xa0);
