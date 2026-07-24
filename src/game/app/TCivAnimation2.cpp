#include "game/app/TCivAnimation2.h"

#include <stdlib.h>

#include "game/ui_core/TView.h"

// SYNTHETIC: IMPERIALISM 0x0049f630
// TCivAnimation2::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049f660
TCivAnimation2::~TCivAnimation2() {}
// SYNTHETIC: IMPERIALISM 0x0049f600
// TCivAnimation2::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049f680
// TCivAnimation2::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivAnimation2, TAnimation)

// NOOP: verified empty in original 0x0049f602 (no standalone TCivAnimation2::TCivAnimation2 body exists: construction is fully inlined into CreateObject 0x0049f600; that address is its operator-new call site)
TCivAnimation2::TCivAnimation2() {}

// FUNCTION: IMPERIALISM 0x0049f6a0
TCivAnimation2::TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag) {
  static const short kStringIds[9] = {14000, 14005, 14011, 14015, 14021,
                                      14026, 14030, 14035, 14040};
  static const int kTicksPerFrame[9] = {5, 15, 10, 7, 15, 15, 7, 10, 10};
  InitializeAnimation(ownerView, rect, 0, kStringIds[kind], kTicksPerFrame[kind], tag);
  kindIndex2c = static_cast<short>(kind);
}

// FUNCTION: IMPERIALISM 0x0049f7c0
void TCivAnimation2::Tick() {
  ++tickCounter10;
  if (tickCounter10 != ticksPerFrame14) {
    return;
  }
  ownerView04->InvalidateCityDialogRectRegion(&screenRect1C, 1);
  ++frameIndex08;
  tickCounter10 = 0;
  switch (kindIndex2c) {
  case 0:
  case 7:
    if (frameIndex08 == 9)
      frameIndex08 = 0;
    break;
  case 1:
    if (frameIndex08 == 7)
      frameIndex08 = 0;
    break;
  case 2:
    if (frameIndex08 == 2)
      frameIndex08 = 0;
    break;
  case 3:
  case 6:
    if (frameIndex08 == 5)
      frameIndex08 = 0;
    break;
  case 4:
    if (frameIndex08 == 6)
      frameIndex08 = 0;
    break;
  case 5:
    if (frameIndex08 == 2 || (frameIndex08 == 1 && rand() % 100 <= 0x31)) {
      frameIndex08 = 0;
    }
    break;
  case 8:
    if (frameIndex08 == 5)
      frameIndex08 = 0;
    break;
  }
}

// FUNCTION: IMPERIALISM 0x0049f8e0
void TCivAnimation2::DrawNextFrame(POINT* offset) {
  static const short kFrameMap[9][12] = {
      {0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0}, {0, 1, 2, 3, 1, 1, 1, 1, 0, 0, 0, 0},
      {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 1, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 1, 0, 0, 1, 2, 0, 0, 0, 0},
      {0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
  };
  short logicalFrame = frameIndex08;
  frameIndex08 = kFrameMap[kindIndex2c][logicalFrame];
  TAnimation::DrawNextFrame(offset);
  frameIndex08 = logicalFrame;
}

// 0x4a0d10 (AddObjectToUiTransientRegistry) and 0x4a0d30 (the registry walker) were
// once claimed here from Ghidra's bucketing, but their receiver is g_pUiAnimator
// (`mov ecx,[0x6a43e0]` at every call site) -- they are TAnimator methods and now
// live in TAnimator.cpp.
