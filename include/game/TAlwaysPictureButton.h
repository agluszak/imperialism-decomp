#pragma once

#include "compat.h"
#include "game/TPictureButton.h"

// VTABLE: IMPERIALISM 0x65e928
class TAlwaysPictureButton : public TPictureButton {
public:
  TAlwaysPictureButton();
  virtual ~TAlwaysPictureButton();
};

ASSERT_SIZE(TAlwaysPictureButton, 0x94);
