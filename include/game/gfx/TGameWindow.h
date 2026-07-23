#pragma once

#include "compat.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656a98
class TGameWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TGameWindow)
  virtual ~TGameWindow() override;

  virtual void Free() override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual CMcWindow* Open() override;
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void UpdateTurnOrderNavigationWindowLayout();
  virtual void NoOpTurnOrderNavigationVtableSlotA();
  virtual void NoOpTurnOrderNavigationVtableSlotB();

  // Only the constructor initializes these (0/0x14/0/0/0); no other confirmed reader/writer.
  short fieldAtA0;
  short fieldAtA2;
  int fieldAtA4;
  int fieldAtA8;
  int fieldAtAc;
  // RTTI proves TGameWindow is exactly TWindow (0xa0) + these 16 bytes (0xb0 total) --
  // no further tail block exists.

  TGameWindow();
};
ASSERT_SIZE(TGameWindow, 0xb0);
