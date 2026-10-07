#pragma once

#include "compat.h"

#include "game/ui_core/TWindow.h"

// VTABLE: IMPERIALISM 0x0064b340
class TFloatWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TFloatWindow)
  virtual ~TFloatWindow() override;
  virtual void Close() override;
  virtual int GetWindowTypeTag();

  TFloatWindow();
};
ASSERT_SIZE(TFloatWindow, 0xa0);
