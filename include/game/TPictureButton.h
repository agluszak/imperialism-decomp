#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

class TPictureButton : public TPictureResourceEntryBase {
public:
  short glyph90;
  short timingWord92;

  TPictureButton();
  virtual ~TPictureButton() override;
};

ASSERT_SIZE(TPictureButton, 0x94);
