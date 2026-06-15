#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65efd8
class TToggleButton : public TPictureResourceEntryBase {
public:
  TToggleButton();
  CRuntimeClass* GetRuntimeClass() override;
  // ~TToggleButton is compiler-generated (implicit virtual dtor).

  virtual void TToggleButton_VtblSlot116(int isPressed, int notifyParent);
};

ASSERT_SIZE(TToggleButton, 0x90);
