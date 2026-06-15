#pragma once

#include "compat.h"
#include "game/TToggleButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x664238
class TBoycottButton : public TToggleButton {
public:
  TBoycottButton();
  CRuntimeClass* GetRuntimeClass() const override;
  // ~TBoycottButton is compiler-generated (implicit virtual dtor).

  void Select(bool isPressed, bool notifyParent) override; // slot 0x1d0
};

ASSERT_SIZE(TBoycottButton, 0x90);
