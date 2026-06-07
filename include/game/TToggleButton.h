#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x65efd8
class TToggleButton : public TPictureResourceEntryBase {
public:
  TToggleButton();
  virtual ~TToggleButton();

  virtual void TToggleButton_VtblSlot116(int isPressed, int notifyParent);
};

ASSERT_SIZE(TToggleButton, 0x90);
