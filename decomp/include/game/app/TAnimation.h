#pragma once

#include "game/gfx/CDib.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

#include "game/ui_core/TBitmapResourceLoader.h"

// VTABLE: IMPERIALISM 0x0064c300
class TAnimation : public TObject {
public:
  DECLARE_DYNCREATE(TAnimation)
  // FUNCTION: IMPERIALISM 0x0049f080
  virtual ~TAnimation() override {}
  virtual void Tick();
  virtual void DrawNextFrame(POINT* offset);
  virtual void LoadFrameIntoBuffer();
  // Object slice verified in 0x49f0c0 (init) and 0x49f140 (per-tick frame flip).
  class TView* ownerView;    // +0x04 view whose rect is invalidated on each frame flip
  short frameIndex;          // +0x08 current frame index; wraps at frameCount
  short frameCount;          // +0x0a frame count (2 for the selection-marker blink)
  short frameResourceBaseId; // +0x0c base resource ID for animation frames
  short padding0E;
  int ticksSinceFrameChange; // +0x10 ticks since the last frame flip
  int ticksPerFrame;         // +0x14 tick interval between frame flips (0xa = marker)
  int registryTag;           // +0x18 animator-registry tag (0x2711 = selection marker)
  RECT screenRect;           // +0x1c on-screen rect invalidated per flip

  // NOOP: verified empty in original 0x0049f022
  TAnimation() {}

  void IAnimation(class TView* ownerViewArg, RECT* rect, short frameCountArg,
                  short frameResourceBaseIdArg, int ticksPerFrameArg, int tag);
};

ASSERT_SIZE(TAnimation, 0x2c);
