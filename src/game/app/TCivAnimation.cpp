#include "game/app/TCivAnimation.h"

#include <stdlib.h>

#include "game/ui_core/TView.h"

// SYNTHETIC: IMPERIALISM 0x0049f480
// TCivAnimation::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x0049f450
// TCivAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049f4d0
// TCivAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivAnimation, TAnimation)

// FUNCTION: IMPERIALISM 0x0049f580
void TCivAnimation::Tick() {
  ++ticksSinceFrameChange;
  if (ticksSinceFrameChange == ticksPerFrame) {
    ownerView->InvalidateCityDialogRectRegion(&screenRect, 1);
    ++frameIndex;
    ticksSinceFrameChange = 0;
    if (frameIndex == frameCount ||
        (frameIndex == randomResetFrame2c && randomResetThreshold2e > (rand() & 0xf))) {
      frameIndex = 0;
    }
  }
}
