#pragma once

#include "compat.h"
#include "game/TToggleButton.h"

// VTABLE: IMPERIALISM 0x664238
struct CRuntimeClass;
class TBoycottButton : public TToggleButton {
public:
  TBoycottButton();
  CRuntimeClass* GetRuntimeClass() override;
  // ~TBoycottButton is compiler-generated (implicit virtual dtor).

  virtual void TToggleButton_VtblSlot116(int isPressed, int notifyParent) override;
};

ASSERT_SIZE(TBoycottButton, 0x90);
