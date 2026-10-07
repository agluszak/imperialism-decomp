#pragma once

#include "compat.h"

#include "game/ui_screens/TOffLimitsPicture.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645650
class TMapUberUberPicture : public TOffLimitsPicture {
public:
  DECLARE_DYNCREATE(TMapUberUberPicture)
  virtual ~TMapUberUberPicture() override;
  virtual void Free() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask);

  TMapUberUberPicture();
};
ASSERT_SIZE(TMapUberUberPicture, 0x94);
