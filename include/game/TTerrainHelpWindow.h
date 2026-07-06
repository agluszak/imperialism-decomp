#pragma once

#include "game/TFloatWindow.h"

// Floating terrain-help window: same 0xa0 layout as TFloatWindow (adds no fields).
// Sibling of THelpWindow; clears g_pHelpMgr's pending terrain-help dialog-view slot on
// CallVoidSlotA0. RTTI: classTTerrainHelpWindow @ 0x00656fb0, base TFloatWindow.
// VTABLE: IMPERIALISM 0x00657500
class TTerrainHelpWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(TTerrainHelpWindow)

  TTerrainHelpWindow();
  virtual ~TTerrainHelpWindow(); // slot 0x01 (scalar deleting destructor 0x504d70)

  void CallVoidSlotA0() override; // slot 0x28 0x504dc0
};

ASSERT_SIZE(TTerrainHelpWindow, 0xa0);
