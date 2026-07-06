#pragma once

#include "game/TWindow.h"

// VTABLE: IMPERIALISM 0x0064b340
class TFloatWindow : public TWindow {
public:
  // === BEGIN GENERATED DECLS (TFloatWindow) ===
  DECLARE_DYNCREATE(TFloatWindow)
  virtual ~TFloatWindow() override;       // slot 0x01 (scalar deleting destructor)
  virtual void CallVoidSlotA0() override; // slot 0x28 0x492330
  virtual int GetWindowTypeTag();         // slot 0x77 0x492310
  // === END GENERATED DECLS (TFloatWindow) ===

  TFloatWindow();
};
