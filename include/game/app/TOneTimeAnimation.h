#pragma once

#include "game/app/TAnimation.h"

class TView;

// One-shot tile-effect animation (explosions, sap blasts) pumped modally by
// TTacticalBattleView::RunOneTimeAnimationModalWaitAndInvalidateCityDialog (0x5a9170).
//
// A TAnimation subclass (RTTI base descriptor 0x64c1f0, CRuntimeClass 0x64c238) with its own
// vtable 0x64c3d0 — DYNCREATE (CreateObject 0x49fcc0). It reuses TAnimation's frame/rect
// slice unchanged and overrides only the per-tick frame advance (slot 0x0a), adding a
// completion flag at +0x2c (object size 0x30 vs TAnimation's 0x2c).
// VTABLE: IMPERIALISM 0x0064c3d0
class TOneTimeAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TOneTimeAnimation)
  virtual ~TOneTimeAnimation() override; // slot 0x01 (scalar deleting destructor); dtor 0x49fd20

  // Override of TAnimation::Tick (slot 0x0a): tick the
  // one-shot animation, invalidate + repaint the target rect on each frame flip, and latch
  // completeFlag once the last frame has played.
  virtual void Tick() override; // slot 0x0a 0x49fde0

  char completeFlag; // 0x2c — set once all frames have played (stops the modal pump)
  char pad2d[3];

  // Field initializer invoked right after `new` (0x49fd60, __thiscall, ret 0x18); fills the
  // inherited TAnimation slice for the one-shot effect.
  void InitializeOneTimeAnimation(TView* view, RECT* rect, short frameCountArg, short effectId,
                                  int tickLimit, int registryTag);
};

ASSERT_SIZE(TOneTimeAnimation, 0x30);
