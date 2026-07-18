#pragma once

#include "game/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x00655928
class TRearFloatWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(TRearFloatWindow)
  virtual ~TRearFloatWindow() override; // slot 0x01 (scalar deleting destructor)
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3,
                                             int arg4) override; // slot 0x46 0x4f3960

  TRearFloatWindow();
};
