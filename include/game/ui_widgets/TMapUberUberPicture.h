#pragma once

#include "compat.h"

#include "game/ui_screens/TOffLimitsPicture.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645650
class TMapUberUberPicture : public TOffLimitsPicture {
public:
  DECLARE_DYNCREATE(TMapUberUberPicture)
  virtual ~TMapUberUberPicture() override;                // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                           // slot 0x07 0x596840
  virtual void DoPostCreate(int arg) override;            // slot 0x37 0x596810
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask); // slot 0x74 0x45d2a0

  // FUNCTION: IMPERIALISM 0x0045d270
  TMapUberUberPicture() : TOffLimitsPicture() {}
};
ASSERT_SIZE(TMapUberUberPicture, 0x94);
