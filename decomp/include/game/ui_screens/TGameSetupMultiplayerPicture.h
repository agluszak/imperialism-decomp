#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661d80
class TGameSetupMultiplayerPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TGameSetupMultiplayerPicture)
  virtual ~TGameSetupMultiplayerPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TGameSetupMultiplayerPicture();
};
ASSERT_SIZE(TGameSetupMultiplayerPicture, 0x94);
