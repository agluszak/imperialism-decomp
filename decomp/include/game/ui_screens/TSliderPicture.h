#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006611e0
class TSliderPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TSliderPicture)
  virtual ~TSliderPicture() override;
  virtual void Draw(RECT* rectBuffer) override;

  TSliderPicture();
};
ASSERT_SIZE(TSliderPicture, 0x94);
