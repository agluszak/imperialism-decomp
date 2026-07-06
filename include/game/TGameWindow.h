#pragma once

#include "game/TDisplayMgr.h"
#include "game/TWindow.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00656a98
class TGameWindow : public TWindow {
public:
  DECLARE_DYNCREATE(TGameWindow)
  virtual ~TGameWindow();

  virtual void Free() override;
  virtual void ForwardParam(int param) override;
  virtual void DispatchSlot9CToLinkedChildren() override;
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
  unsigned char turnNavTail[0x1e4 - 0xb0];

  TGameWindow();
};

