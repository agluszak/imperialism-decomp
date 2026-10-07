#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660918
class TBackgroundPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TBackgroundPicture)
  virtual ~TBackgroundPicture() override;
  virtual void Draw(RECT* rectBuffer) override;

  TBackgroundPicture();
};
ASSERT_SIZE(TBackgroundPicture, 0x94);
