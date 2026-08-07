#pragma once

#include "compat.h"

#include "game/app/TFocusAnimation.h"

struct TQuickDrawSurfaceContext;

// Transitional focus-animation helper (factory 0x004a0460). Shares the completion callback
// slot layout with TFocusAnimation (vtable index 5 / byte offset 0x14).
// VTABLE: IMPERIALISM 0x0064c498
class TTransFocusAnimation : public TFocusAnimation {
  DECLARE_DYNCREATE(TTransFocusAnimation)

public:
  // Default constructor for MFC dynamic creation
  TTransFocusAnimation() : TFocusAnimation() {
    ownerView = nullptr;
    frameIndex = 0;
    frameCount = 0;
    frameResourceBaseId = 0;
    ticksSinceFrameChange = 0;
    ticksPerFrame = 0;
    registryTag = 0;
    screenRect.left = 0;
    screenRect.top = 0;
    screenRect.right = 0;
    screenRect.bottom = 0;
    enabledFlag = 1;
    transientSurfaceContext = 0;
    insetBitmapSurface = 0;
  }

  TTransFocusAnimation(TView* target, RECT* bounds, short f0a, short f0c, int tickLimit, int f18);
  // FUNCTION: IMPERIALISM 0x004a0460
  virtual ~TTransFocusAnimation() override {}

  virtual void Free() override;                       // slot 7 / 0x1c
  virtual void DrawNextFrame(POINT* offset) override; // slot 11 / 0x2c 0x4a0810
  virtual void IdleDraw() override;                   // slot 13 / 0x34 0x4a0770

  // TTransFocusAnimation-introduced virtual (past TFocusAnimation's own slots).
  virtual void UpdateBackground(); // slot 0x3c 0x4a05c0

  TQuickDrawSurfaceContext* transientSurfaceContext; // 0x30 — offscreen scratch surface
  TQuickDrawSurfaceContext* insetBitmapSurface;      // 0x34 — bitmap resource f0c's surface
};
ASSERT_SIZE(TTransFocusAnimation, 0x38);
