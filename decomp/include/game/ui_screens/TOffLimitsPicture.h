#pragma once

#include "compat.h"

#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660fb0
class TOffLimitsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TOffLimitsPicture)
  virtual ~TOffLimitsPicture() override;        // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                 // slot 0x07 0x573900
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x573850
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x573890
  virtual void ForwardCopyRgn(RgnHandle srcRegion); // slot 0x73 0x573940
  RgnHandle ownClipRegion;

  TOffLimitsPicture();
};
ASSERT_SIZE(TOffLimitsPicture, 0x94);
