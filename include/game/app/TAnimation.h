#pragma once

#include "game/gfx/CDib.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

#include "game/ui_core/TBitmapResourceLoader.h"

// VTABLE: IMPERIALISM 0x0064c300
class TAnimation : public TObject {
public:
  DECLARE_DYNCREATE(TAnimation)
  virtual ~TAnimation() override;            // slot 0x01 (scalar deleting destructor)
  virtual void Tick();                       // slot 0x0a 0x49f140
  virtual void DrawNextFrame(POINT* offset); // slot 0x0b 0x49f190
  virtual void LoadFrameIntoBuffer();        // slot 0x0c 0x49f2d0
  // Object slice verified in 0x49f0c0 (init) and 0x49f140 (per-tick frame flip).
  class TView* ownerView04; // +0x04 view whose rect is invalidated on each frame flip
  short frameIndex08;       // +0x08 current frame index; wraps at frameCount0A
  short frameCount0A;       // +0x0a frame count (2 for the selection-marker blink)
  short field0C;            // +0x0c 4th ctor arg; 0 at the only known call site
  short pad0E;              // +0x0e
  int tickCounter10;        // +0x10 ticks since the last frame flip
  int ticksPerFrame14;      // +0x14 tick interval between frame flips (0xa = marker)
  int registryTag18;        // +0x18 animator-registry tag (0x2711 = selection marker)
  RECT screenRect1C;        // +0x1c on-screen rect invalidated per flip

  // NOOP: verified empty in original 0x0049f022 (no standalone TAnimation::TAnimation body exists: construction is fully inlined into CreateObject 0x0049f020; that address is its operator-new call site)
  TAnimation() {}

  // Post-construction init used by the tactical selection marker (0x5a9bb0): owner
  // view, screen rect, frame count, mode word, tick interval, registry tag.
  // 0x0049f0c0, __thiscall.
  void InitializeAnimation(class TView* ownerView, RECT* rect, short frameCount, short param4,
                           int ticksPerFrame, int tag);
};

ASSERT_SIZE(TAnimation, 0x2c);
