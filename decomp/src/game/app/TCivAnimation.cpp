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

// FUNCTION: IMPERIALISM 0x0049f4f0
void TCivAnimation::ICivAnimation(TView* ownerViewArg, RECT* rect, short frameCountArg,
                                  short frameResourceBaseIdArg, int ticksPerFrameArg, int tag,
                                  short randomResetFrameArg, short randomResetThresholdArg) {
  ownerView = ownerViewArg;
  screenRect = *rect;
  frameCount = frameCountArg;
  frameResourceBaseId = frameResourceBaseIdArg;
  frameIndex = 0;
  ticksSinceFrameChange = 0;
  ticksPerFrame = ticksPerFrameArg;
  registryTag = tag;
  randomResetFrame2c = randomResetFrameArg;
  randomResetThreshold2e = randomResetThresholdArg;
}

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
