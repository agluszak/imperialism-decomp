#include "game/app/TCivAnimation2.h"

#include <stdlib.h>

#include "game/ui_core/TView.h"

IMPLEMENT_DYNCREATE(TCivAnimation2, TAnimation)

// FUNCTION: IMPERIALISM 0x0049f6a0
TCivAnimation2::TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag) {
  static const short kStringIds[9] = {14000, 14005, 14011, 14015, 14021,
                                      14026, 14030, 14035, 14040};
  static const int kTicksPerFrame[9] = {5, 15, 10, 7, 15, 15, 7, 10, 10};
  IAnimation(ownerView, rect, 0, kStringIds[kind], kTicksPerFrame[kind], tag);
  kindIndex = static_cast<short>(kind);
}

// FUNCTION: IMPERIALISM 0x0049f7c0
void TCivAnimation2::Tick() {
  ++ticksSinceFrameChange;
  if (ticksSinceFrameChange != ticksPerFrame) {
    return;
  }
  ownerView->InvalidateCityDialogRectRegion(&screenRect, 1);
  ++frameIndex;
  ticksSinceFrameChange = 0;
  switch (kindIndex) {
  case 0:
  case 7:
    if (frameIndex == 9)
      frameIndex = 0;
    break;
  case 1:
    if (frameIndex == 7)
      frameIndex = 0;
    break;
  case 2:
    if (frameIndex == 2)
      frameIndex = 0;
    break;
  case 3:
  case 6:
    if (frameIndex == 5)
      frameIndex = 0;
    break;
  case 4:
    if (frameIndex == 6)
      frameIndex = 0;
    break;
  case 5:
    if (frameIndex == 2 || (frameIndex == 1 && rand() % 100 <= 0x31)) {
      frameIndex = 0;
    }
    break;
  case 8:
    if (frameIndex == 5)
      frameIndex = 0;
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
  short logicalFrame = frameIndex;
  frameIndex = kFrameMap[kindIndex][logicalFrame];
  TAnimation::DrawNextFrame(offset);
  frameIndex = logicalFrame;
}

// 0x4a0d10 (AddAnimation) and 0x4a0d30 (the registry walker) were
// once claimed here from Ghidra's bucketing, but their receiver is g_pUiAnimator
// (`mov ecx,[0x6a43e0]` at every call site) -- they are TAnimator methods and now
// live in TAnimator.cpp.
