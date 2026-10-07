#pragma once

#include "compat.h"

#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660fb0
class TOffLimitsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TOffLimitsPicture)
  virtual ~TOffLimitsPicture() override;
  virtual void Free() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void SetRgn(RgnHandle srcRegion);
  RgnHandle ownClipRegion;

  TOffLimitsPicture();
};
ASSERT_SIZE(TOffLimitsPicture, 0x94);
