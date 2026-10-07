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
  class TView* ownerView;    // view whose rect is invalidated on each frame flip
  short frameIndex;          // current frame index; wraps at frameCount
  short frameCount;          // frame count (2 for the selection-marker blink)
  short frameResourceBaseId; // base resource ID for animation frames
  int ticksSinceFrameChange; // ticks since the last frame flip
  int ticksPerFrame;         // tick interval between frame flips (0xa = marker)
  int registryTag;           // animator-registry tag (0x2711 = selection marker)
  RECT screenRect;           // on-screen rect invalidated per flip

  // NOOP: verified empty in original 0x0049f022
  TAnimation() {}

  void IAnimation(class TView* ownerViewArg, RECT* rect, short frameCountArg,
                  short frameResourceBaseIdArg, int ticksPerFrameArg, int tag);
};

ASSERT_SIZE(TAnimation, 0x2c);
