#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660918
class TBackgroundPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TBackgroundPicture)
  virtual ~TBackgroundPicture() override;       // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x572d00

  TBackgroundPicture();
};
ASSERT_SIZE(TBackgroundPicture, 0x94);
