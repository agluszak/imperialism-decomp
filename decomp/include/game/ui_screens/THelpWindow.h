#pragma once

#include "game/ui_core/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x006572c0
class THelpWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(THelpWindow)

  THelpWindow();
  virtual ~THelpWindow() override; // slot 0x01 (scalar deleting destructor 0x504c20)

  void Close() override; // slot 0x28 0x504c70
};

ASSERT_SIZE(THelpWindow, 0xa0);
