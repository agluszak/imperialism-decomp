#pragma once

#include "compat.h"
#include "game/ui_screens/TToggleButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x664238
class TBoycottButton : public TToggleButton {
public:
  virtual ~TBoycottButton() override; // slot 0x01 (scalar deleting destructor)
  TBoycottButton();
  DECLARE_DYNCREATE(TBoycottButton)

  void Select(bool isPressed, bool notifyParent) override; // slot 0x1d0
};

ASSERT_SIZE(TBoycottButton, 0x90);
