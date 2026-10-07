#pragma once

#include "compat.h"

#include "game/ui_core/TFloatWindow.h"

// VTABLE: IMPERIALISM 0x00655928
class TRearFloatWindow : public TFloatWindow {
public:
  DECLARE_DYNCREATE(TRearFloatWindow)
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;

  TRearFloatWindow();
};
ASSERT_SIZE(TRearFloatWindow, 0xa0);
