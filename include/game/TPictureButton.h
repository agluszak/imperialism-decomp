#pragma once

#include "game/TControl.h"

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureButton : public TControl {
public:
  short glyphBase84;
  char pad_TPictureButton_86[0xa];
  short glyph90;
  short timingWord92;

  TPictureButton();
  virtual ~TPictureButton();
};
