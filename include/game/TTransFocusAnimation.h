#pragma once

#include "game/mfc.h"

class TView;

// Transitional focus-animation helper (factory 0x004a0460). Shares the completion callback
// slot layout with TFocusAnimation (vtable index 5 / byte offset 0x14).
// VTABLE: IMPERIALISM 0x0064c498
class TTransFocusAnimation : public CObject {
public:
#define TTRANS_FOCUS_ANIMATION_DUMMY(n) virtual void TTransFocusAnimationDummy##n() = 0
  TTRANS_FOCUS_ANIMATION_DUMMY(00);
  TTRANS_FOCUS_ANIMATION_DUMMY(01);
  TTRANS_FOCUS_ANIMATION_DUMMY(02);
  TTRANS_FOCUS_ANIMATION_DUMMY(03);
  TTRANS_FOCUS_ANIMATION_DUMMY(04);
#undef TTRANS_FOCUS_ANIMATION_DUMMY

  virtual void DispatchCompletionRecordSlot14(int* completionRecord); // 0x14

  TView* scopedRenderTarget; // 0x04 — render-target view for the scoped QuickDraw context
  short field08;            // 0x08
  short field0a;            // 0x0a
  short field0c;            // 0x0c
  char pad_0e[2];
  int field10;      // 0x10
  int field14;      // 0x14
  int field18;      // 0x18
  int sourceLeft;   // 0x1c
  int sourceTop;    // 0x20
  int sourceRight;  // 0x24
  int sourceBottom; // 0x28
  char pad_2c[4];
  int transientSurfaceContext; // 0x30

  void BlitTransientSurfaceToPrimaryRenderContextWithClip();
  void RenderFocusAnimationFrameWithScopedQuickDraw();
};
