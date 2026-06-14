#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x65efd8
struct CRuntimeClass;
class TToggleButton : public TPictureResourceEntryBase {
public:
  TToggleButton();
  CRuntimeClass* GetRuntimeClass() override;
  // ~TToggleButton is compiler-generated (implicit virtual dtor).

  virtual void TToggleButton_VtblSlot116(int isPressed, int notifyParent);
};

ASSERT_SIZE(TToggleButton, 0x90);
