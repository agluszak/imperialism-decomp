#pragma once

#include "game/TDisplayMgr.h"
#include "game/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656a98
class TGameWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TGameWindow)
  virtual ~TGameWindow() override;

  virtual void Free() override;
  virtual void ForwardParam(int param) override;
  virtual CMcWindow* Open() override;
  virtual char DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) override;
  virtual char DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                         int arg4) override;
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
