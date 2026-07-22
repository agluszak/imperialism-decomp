#pragma once

#include "compat.h"
#include "game/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656ce8
class TDlgWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TDlgWindow)
  virtual ~TDlgWindow() override; // slot 0x01 (scalar deleting destructor)
  virtual void AssertMcAppUILine2358(int unusedArg) override; // slot 0x72 0x5003a0
  // RTTI oracle: sizeof(TDlgWindow) == 0xa0, identical to TWindow -- this class adds no
  // data members of its own; its ctor (0x500320) just installs its own vtable over the
  // real TWindow base construction.

  TDlgWindow();
};

ASSERT_SIZE(TDlgWindow, 0xa0);
