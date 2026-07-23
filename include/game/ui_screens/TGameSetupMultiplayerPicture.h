#pragma once

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661d80
class TGameSetupMultiplayerPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TGameSetupMultiplayerPicture)
  virtual ~TGameSetupMultiplayerPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00576230
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x575fb0

  TGameSetupMultiplayerPicture();
};
