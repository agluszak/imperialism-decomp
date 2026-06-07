#pragma once

#include "compat.h"
#include "game/TToggleButton.h"

// VTABLE: IMPERIALISM 0x664470
class T2PictToggleButton : public TToggleButton {
public:
  T2PictToggleButton();
  virtual ~T2PictToggleButton();
};

ASSERT_SIZE(T2PictToggleButton, 0x90);
