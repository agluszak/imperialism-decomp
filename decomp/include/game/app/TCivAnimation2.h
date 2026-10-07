#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation2)
  // FUNCTION: IMPERIALISM 0x0049f660
  virtual ~TCivAnimation2() override {}
  virtual void Tick() override;
  virtual void DrawNextFrame(POINT* offset) override;
  short kindIndex;
  short pad2e;

  // NOOP: verified empty in original 0x0049f602
  TCivAnimation2() {}

  // Forwards to TAnimation::IAnimation with no frames; Tick drives the animation itself.
  TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag);
};

ASSERT_SIZE(TCivAnimation2, 0x30);
