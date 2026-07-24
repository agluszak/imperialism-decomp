#pragma once

#include "compat.h"

#include "game/ui_screens/TNoHilitePicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006611e0
class TSliderPicture : public TNoHilitePicture {
public:
  DECLARE_DYNCREATE(TSliderPicture)
  virtual ~TSliderPicture() override;           // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x573aa0

  TSliderPicture();
};
ASSERT_SIZE(TSliderPicture, 0x94);
