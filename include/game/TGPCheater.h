#pragma once

#include "game/military_ui/TCheater.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064f050
class TGPCheater : public TCheater {
public:
  DECLARE_DYNCREATE(TGPCheater)
  virtual ~TGPCheater() override; // slot 0x01 (scalar deleting destructor)

  TGPCheater();
};
