#pragma once

#include "game/ui_core/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x00655928
class TRearFloatWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(TRearFloatWindow)
  virtual ~TRearFloatWindow() override; // slot 0x01 (scalar deleting destructor)
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin) override; // slot 0x46 0x4f3960

  TRearFloatWindow();
};
