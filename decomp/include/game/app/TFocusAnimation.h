#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"

class TView;

// VTABLE: IMPERIALISM 0x0064c450
class TFocusAnimation : public TAnimation {
  DECLARE_DYNCREATE(TFocusAnimation)
public:
  // FUNCTION: IMPERIALISM 0x004a0080
  ~TFocusAnimation() override {}
  TFocusAnimation() : TAnimation(), enabledFlag(1) {}

  virtual void Tick() override;
  virtual void DrawNextFrame(POINT* unusedOffset) override;
  virtual void IdleDraw();
  virtual void ClipAndPaste();

  void IFocusAnimation(TView* ownerView, RECT* rect, short frameCount, short frameResourceBaseId,
                       int ticksPerFrame, int registryTag);

  bool enabledFlag;

  char padding2D[3];
};
ASSERT_SIZE(TFocusAnimation, 0x30);
