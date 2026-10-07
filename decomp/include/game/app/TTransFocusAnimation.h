#pragma once

#include "compat.h"

#include "game/app/TFocusAnimation.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x0064c498
class TTransFocusAnimation : public TFocusAnimation {
  DECLARE_DYNCREATE(TTransFocusAnimation)

public:
  // Default constructor for MFC dynamic creation
  TTransFocusAnimation() : TFocusAnimation(), transientSurfaceContext(0), insetBitmapSurface(0) {}

  void ITransFocusAnimation(TView* target, RECT* bounds, short frameCount,
                            short frameResourceBaseId, int ticksPerFrame, int registryTag);
  // FUNCTION: IMPERIALISM 0x004a0460
  virtual ~TTransFocusAnimation() override {}

  virtual void Free() override;
  virtual void DrawNextFrame(POINT* offset) override;
  virtual void IdleDraw() override;

  // TTransFocusAnimation-introduced virtual (past TFocusAnimation's own slots).
  virtual void UpdateBackground();

  TQuickDrawSurfaceContext* transientSurfaceContext; // offscreen scratch surface
  TQuickDrawSurfaceContext* insetBitmapSurface;      // bitmap resource f0c's surface
};
ASSERT_SIZE(TTransFocusAnimation, 0x38);
