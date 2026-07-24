#pragma once

#include "compat.h"

#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c350
class TCivAnimation : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation)
  virtual ~TCivAnimation() override; // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;      // slot 0x0a 0x49f580

  TCivAnimation();

  short randomResetFrame2c;     // +0x2c frame that may restart the cycle early
  short randomResetThreshold2e; // +0x2e threshold compared with rand() & 0xf
};
ASSERT_SIZE(TCivAnimation, 0x30);
