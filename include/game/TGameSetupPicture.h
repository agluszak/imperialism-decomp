#pragma once

#include "game/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661b50
class TGameSetupPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TGameSetupPicture)
  virtual ~TGameSetupPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00575900
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5758e0

  TGameSetupPicture();
};
