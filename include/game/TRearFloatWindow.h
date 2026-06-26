#pragma once

#include "game/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x00655928
class TRearFloatWindow : public TFloatWindow {
public:
  // === BEGIN GENERATED DECLS (TRearFloatWindow) ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x4f38c0
  virtual ~TRearFloatWindow() override;                    // slot 0x01 (scalar deleting destructor)
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4) override; // slot 0x46 0x4f3960
  // === END GENERATED DECLS (TRearFloatWindow) ===

  static TView* CreateTRearFloatWindowInstance();

  TRearFloatWindow();
};
