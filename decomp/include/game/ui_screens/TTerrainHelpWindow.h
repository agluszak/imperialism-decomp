#pragma once

#include "game/ui_core/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x00657500
class TTerrainHelpWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(TTerrainHelpWindow)

  TTerrainHelpWindow();
  virtual ~TTerrainHelpWindow() override;

  void Close() override;
};

ASSERT_SIZE(TTerrainHelpWindow, 0xa0);
