#pragma once

#include "compat.h"

#include "game/ui_core/TBehavior.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eac8
class THotspotBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(THotspotBehavior)
  // FUNCTION: IMPERIALISM 0x004b0be0
  virtual ~THotspotBehavior() override {} // slot 0x01 (scalar deleting destructor)
  virtual unsigned char DoSetCursor(CPoint* point,
                                    RgnHandle region); // slot 0x0e 0x4b0c00

  THotspotBehavior();
};
ASSERT_SIZE(THotspotBehavior, 0x10);
