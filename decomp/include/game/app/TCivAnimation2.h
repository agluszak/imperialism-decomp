#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/mfc.h"

// Civilian animation state machine registered through TAnimator as a TAnimation.
// The RTTI base edge and vtable confirm this inheritance.
// VTABLE: IMPERIALISM 0x0064c390
class TCivAnimation2 : public TAnimation {
public:
  DECLARE_DYNCREATE(TCivAnimation2)
  // FUNCTION: IMPERIALISM 0x0049f660
  virtual ~TCivAnimation2() override {}               // slot 0x01 (scalar deleting destructor)
  virtual void Tick() override;                       // slot 0x0a 0x49f7c0
  virtual void DrawNextFrame(POINT* offset) override; // slot 0x0b 0x49f8e0
  // The kind selects the frame schedule in Tick and the sprite frame map in
  // DrawNextFrame. TAnimation's slice ends at 0x2c.
  short kindIndex2c; // +0x2c
  short pad2e;       // +0x2e

  // NOOP: verified empty in original 0x0049f602. Used by DYNCREATE.
  TCivAnimation2() {}

  // Real ctor (0x49f6a0): looks up a per-kind (stringId, ticksPerFrame) pair from two
  // 9-entry tables baked into the original as immediate stores (kind 0..8 -- battle
  // report civ animation variants) and forwards them to the already-ported
  // TAnimation::IAnimation with frameCount pinned to 0 (this class
  // overrides Tick itself, so the inherited
  // frame-index scheme is unused). Confirmed against both call sites
  // (OrphanTiny_ReturnZero_0048a730 and Draw): param_1 is the enclosing
  // TView, param_2 a RECT computed from a (x,y) origin, param_3 the kind index read
  // from another object's +0x4 field, param_4 an opaque tag forwarded verbatim.
  TCivAnimation2(TView* ownerView, RECT* rect, int kind, int tag);
};

ASSERT_SIZE(TCivAnimation2, 0x30);
