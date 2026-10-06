#pragma once

#include "compat.h"

#include "game/gfx/TAdorner.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006566f0
class TColorFill : public TAdorner {
public:
  DECLARE_DYNCREATE(TColorFill)
  virtual ~TColorFill() override; // slot 0x01 (scalar deleting destructor)
  virtual void Draw(TView* view, const RECT& bounds) override; // slot 0x0c 0x4ff1c0

  // NOOP: verified empty in original 0x004ff10b
  TColorFill() {}
};
ASSERT_SIZE(TColorFill, 0xc);
