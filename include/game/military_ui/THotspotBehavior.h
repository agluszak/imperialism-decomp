#pragma once

#include "game/ui_core/TBehavior.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064eac8
class THotspotBehavior : public TBehavior {
public:
  DECLARE_DYNCREATE(THotspotBehavior)
  virtual ~THotspotBehavior() override; // slot 0x01 (scalar deleting destructor)
  virtual unsigned char DoSetCursor(CPoint* point,
                                    RgnHandle region); // slot 0x0e 0x4b0c00

  THotspotBehavior();
};
