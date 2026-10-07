#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00661b50
class TGameSetupPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TGameSetupPicture)
  virtual ~TGameSetupPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TGameSetupPicture();
};
ASSERT_SIZE(TGameSetupPicture, 0x94);
