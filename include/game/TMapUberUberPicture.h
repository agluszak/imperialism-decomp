#pragma once

#include "game/TOffLimitsPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00645650
class TMapUberUberPicture : public TOffLimitsPicture {
public:
  DECLARE_DYNCREATE(TMapUberUberPicture)
  virtual ~TMapUberUberPicture() override;           // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                      // slot 0x07 0x596840
  virtual void DoPostCreate(int arg) override;       // slot 0x37 0x596810
  virtual void AutoScrollByEdgeMask(short edgeMask); // slot 0x74 0x45d2a0

  TMapUberUberPicture();
};
