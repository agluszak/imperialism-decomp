#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c350
class TCivAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation)
  // FUNCTION: IMPERIALISM 0x0049f4b0
  virtual ~TCivAnimation() override {}
  virtual void Tick() override;

  // NOOP: verified empty in original 0x0049f452
  TCivAnimation() {}

  short randomResetFrame;     // frame that may restart the cycle early
  short randomResetThreshold; // threshold compared with rand() & 0xf

  void ICivAnimation(TView* ownerViewArg, RECT* rect, short frameCountArg,
                     short frameResourceBaseIdArg, int ticksPerFrameArg, int tag,
                     short randomResetFrameArg, short randomResetThresholdArg);
};
ASSERT_SIZE(TCivAnimation, 0x30);
