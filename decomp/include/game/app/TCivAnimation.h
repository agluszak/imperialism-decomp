#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c350
class TCivAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation)
  // FUNCTION: IMPERIALISM 0x0049f4b0
  virtual ~TCivAnimation() override {} // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;        // slot 0x0a 0x49f580

  // NOOP: verified empty in original 0x0049f452 (no standalone TCivAnimation::TCivAnimation body exists: construction is fully inlined into CreateObject 0x0049f450; that address is its operator-new call site)
  TCivAnimation() {}

  short randomResetFrame2c;     // +0x2c frame that may restart the cycle early
  short randomResetThreshold2e; // +0x2e threshold compared with rand() & 0xf

  // Second-phase init duplicating TAnimation::IAnimation's assignment pattern plus
  // the two random-reset fields (retail emits the stores inline, no IAnimation
  // call). Dead standalone COMDAT at 0x0049f4f0.
  void ICivAnimation(TView* ownerViewArg, RECT* rect, short frameCountArg,
                     short frameResourceBaseIdArg, int ticksPerFrameArg, int tag,
                     short randomResetFrameArg, short randomResetThresholdArg);
};
ASSERT_SIZE(TCivAnimation, 0x30);
