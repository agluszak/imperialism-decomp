#pragma once

#include "game/ui_core/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x00657500
class TTerrainHelpWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(TTerrainHelpWindow)

  TTerrainHelpWindow();
  virtual ~TTerrainHelpWindow() override; // slot 0x01 (scalar deleting destructor 0x504d70)

  void Close() override; // slot 0x28 0x504dc0
};

ASSERT_SIZE(TTerrainHelpWindow, 0xa0);
