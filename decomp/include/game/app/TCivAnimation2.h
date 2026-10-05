#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation2)
  // FUNCTION: IMPERIALISM 0x0049f660
  virtual ~TCivAnimation2() override {}               // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;                       // slot 0x0a 0x49f7c0
  virtual void DrawNextFrame(POINT* offset) override; // slot 0x0b 0x49f8e0
  short kindIndex; // +0x2c
  short pad2e;     // +0x2e

  // NOOP: verified empty in original 0x0049f602 (no standalone TCivAnimation2::TCivAnimation2 body exists: construction is fully inlined into CreateObject 0x0049f600; that address is its operator-new call site)
  TCivAnimation2() {}

  // Forwards to TAnimation::IAnimation with no frames; Tick drives the animation itself.
  TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag);
};

ASSERT_SIZE(TCivAnimation2, 0x30);
