#pragma once

#include "game/ui_core/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x006572c0
class THelpWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(THelpWindow)

  THelpWindow();
  virtual ~THelpWindow() override;

  void Close() override;
};

ASSERT_SIZE(THelpWindow, 0xa0);
