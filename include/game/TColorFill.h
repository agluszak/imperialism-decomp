#pragma once

#include "game/TAdorner.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006566f0
class TColorFill : public TAdorner {
public:
  DECLARE_DYNCREATE(TColorFill)
  virtual ~TColorFill() override; // slot 0x01 (scalar deleting destructor)
  // Real override, not a no-op: a nil-pointer assert guarded by a private static flag (see
  // TColorFill.cpp) -- the base class's shared invalidation-flag-pulse default does not
  // apply here.
  virtual void Draw(TView* view, const RECT& bounds) override; // slot 0x0c 0x4ff1c0

  TColorFill();
};
