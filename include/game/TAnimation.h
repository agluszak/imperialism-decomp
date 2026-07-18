#pragma once

#include "game/CDib.h"
#include "game/TObject.h"
#include "game/mfc.h"

struct TBitmapResourceLoaderState {
  unsigned char flags;
  unsigned char pad05[3];
  RECT bitmapRect;
  CDib* bitmapResource;
  short bitmapResourceId;
  short pad1e;

  explicit TBitmapResourceLoaderState(unsigned short resourceId)
      : flags(0), bitmapResource(nullptr), bitmapResourceId(static_cast<short>(resourceId)) {}
};

// Lightweight bitmap loader allocated by CreateBitmapResourceLoaderHandle. Confirmed
// exactly 3 slots (dword at +0xc, right after the 3 declared virtuals, reads as a
// literal NULL); no destructor slot in the original.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x0064c340
class TBitmapResourceLoader : public TBitmapResourceLoaderState {
public:
  explicit TBitmapResourceLoader(unsigned short resourceId)
      : TBitmapResourceLoaderState(resourceId) {
    EnsureBitmapResourceLoadedAndCopyRectSize();
  }

  ~TBitmapResourceLoader() {
    ReleaseBitmapResource();
  }

  virtual void EnsureBitmapResourceLoadedAndCopyRectSize();         // slot 0x00 0x495b70
  virtual void ReleaseBitmapResource();                             // slot 0x01 0x495c00
  virtual undefined TemporarilyClearAndRestoreUiInvalidationFlag(); // slot 0x02 0x4a1100
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(TBitmapResourceLoaderState, 0x1c);
ASSERT_SIZE(TBitmapResourceLoader, 0x20);

// VTABLE: IMPERIALISM 0x0064c300
class TAnimation : public TObject {
public:
  DECLARE_DYNCREATE(TAnimation)
  virtual ~TAnimation() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined AdvanceAnimationTickAndInvalidateOnFrameFlip();          // slot 0x0a 0x49f140
  virtual undefined RenderBattleReportInsetWithPaletteShift();               // slot 0x0b 0x49f190
  virtual undefined RenderBattleReportViewSurfaceSpriteWithResourceHandle(); // slot 0x0c 0x49f2d0
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

  TAnimation() {}

  // Post-construction init used by the tactical selection marker (0x5a9bb0): owner
  // view, screen rect, frame count, mode word, tick interval, registry tag.
  // 0x0049f0c0, __thiscall.
  void ConstructTAnimationBaseState(class TView* ownerView, RECT* rect, short frameCount,
                                    short param4, int ticksPerFrame, int tag);
};

TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId);

ASSERT_SIZE(TAnimation, 0x2c);
