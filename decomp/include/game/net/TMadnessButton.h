#pragma once

#include "compat.h"

#include "game/ui_screens/TCzechBox.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641df0
class TMadnessButton : public TCzechBox {
public:
  DECLARE_DYNCREATE(TMadnessButton)
  virtual ~TMadnessButton() override;
  virtual void DoPostCreate(int arg) override;
  virtual void CheckTheLook(unsigned char refreshNow) override;

  TMadnessButton();

  int initialPictureId; // snapshot of glyphBase captured during DoPostCreate
};
ASSERT_SIZE(TMadnessButton, 0x9c);
