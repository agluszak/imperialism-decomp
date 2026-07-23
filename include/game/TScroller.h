#pragma once

#include "game/TView.h"
#include "game/ui_tags_common.h"

// Scroll-host view: same 0x60 layout as TView (adds no fields); reuses the shared
// TEventHandler/TView slots for its placement bookkeeping. RTTI: classTScroller @
// 0x006495b8, base TView.
// VTABLE: IMPERIALISM 0x00649a68
class TScroller : public TView {
public:
  DECLARE_DYNCREATE(TScroller)

  TScroller();
  virtual ~TScroller() override; // slot 0x01 (scalar deleting destructor 0x48cad0)

  // Non-virtual placement initializer (0x48cbb0): tags the control ('    '), links the
  // owner panel, copies offset/size layout pairs, and attaches self as a child control.
  void InitializeScrollerPlacement(TView* owner, int* offsetLayout, int* sizeLayout);
};

ASSERT_SIZE(TScroller, 0x60);
