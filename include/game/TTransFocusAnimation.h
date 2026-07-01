#pragma once

#include "game/TFocusAnimation.h"

// Transitional focus-animation helper (factory 0x004a0460). Shares the completion callback
// slot layout with TFocusAnimation (vtable index 5 / byte offset 0x14).
// VTABLE: IMPERIALISM 0x0064c498
class TTransFocusAnimation : public TFocusAnimation {
  DECLARE_DYNCREATE(TTransFocusAnimation)

public:
  TTransFocusAnimation();
  TTransFocusAnimation(TView* target, RECT* bounds, short f0a, short f0c, int tickLimit, int f18);
  virtual ~TTransFocusAnimation() override;

  virtual void Free() override; // slot 7 / 0x1c
  virtual undefined RenderBattleReportInsetWithPaletteShift() override; // slot 11 / 0x2c
  virtual void VTableSlot0D() override; // slot 13 / 0x34

  // TTransFocusAnimation-introduced virtual (past TFocusAnimation's own slots).
  virtual void BlitTransientSurfaceToPrimaryRenderContextWithClip(); // slot 0x3c 0x4a05c0

  int transientSurfaceContext; // 0x30
  int field34;                 // 0x34
};
