#pragma once

#include "compat.h"

#include "game/ui_screens/TCzechBox.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00641df0
class TMadnessButton : public TCzechBox {
public:
  DECLARE_DYNCREATE(TMadnessButton)
  virtual ~TMadnessButton() override;          // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x54eaf0
  virtual void CheckTheLook(unsigned char refreshNow) override; // slot 0x76 0x54eb30

  TMadnessButton();

  int initialPictureId; // 0x98, snapshot of glyphBase84 captured during DoPostCreate
};
ASSERT_SIZE(TMadnessButton, 0x9c);
