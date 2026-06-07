#pragma once

#include "compat.h"
#include "game/TToggleButton.h"

// VTABLE: IMPERIALISM 0x664238
class TBoycottButton : public TToggleButton {
public:
  TBoycottButton();
  virtual ~TBoycottButton();

  virtual void TToggleButton_VtblSlot116(int isPressed, int notifyParent);
};

ASSERT_SIZE(TBoycottButton, 0x90);
