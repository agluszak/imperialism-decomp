#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065d4b0
class TShipPlacard : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TShipPlacard)
  virtual ~TShipPlacard() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5692f0

  TShipPlacard();
};
