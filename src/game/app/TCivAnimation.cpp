#include "game/TCivAnimation.h"

#include <stdlib.h>

#include "game/TView.h"

// SYNTHETIC: IMPERIALISM 0x0049f480
// TCivAnimation::`scalar deleting destructor'
TCivAnimation::~TCivAnimation() {}
// SYNTHETIC: IMPERIALISM 0x0049f450
// TCivAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049f4d0
// TCivAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivAnimation, TAnimation)

TCivAnimation::TCivAnimation() {}

// FUNCTION: IMPERIALISM 0x0049f580
void TCivAnimation::Tick() {
  ++tickCounter10;
  if (tickCounter10 == ticksPerFrame14) {
    ownerView04->InvalidateCityDialogRectRegion(&screenRect1C, 1);
    ++frameIndex08;
    tickCounter10 = 0;
    if (frameIndex08 == frameCount0A ||
        (frameIndex08 == randomResetFrame2c && randomResetThreshold2e > (rand() & 0xf))) {
      frameIndex08 = 0;
    }
  }
}
