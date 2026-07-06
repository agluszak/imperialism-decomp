#pragma once

#include "game/TFloatWindow.h"

// Floating in-game help window: same 0xa0 layout as TFloatWindow (adds no fields).
// On CallVoidSlotA0 (close/reset) it also clears g_pHelpMgr's pending general-help
// dialog-view slot. RTTI: classTHelpWindow @ 0x00656f98, base TFloatWindow.
// VTABLE: IMPERIALISM 0x006572c0
class THelpWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(THelpWindow)

  THelpWindow();
  virtual ~THelpWindow(); // slot 0x01 (scalar deleting destructor 0x504c20)

  void CallVoidSlotA0() override; // slot 0x28 0x504c70
};

ASSERT_SIZE(THelpWindow, 0xa0);
