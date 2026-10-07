#pragma once

#include "compat.h"
#include "game/ui_screens/TToggleButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x664238
class TBoycottButton : public TToggleButton {
public:
  virtual ~TBoycottButton() override;
  TBoycottButton();
  DECLARE_DYNCREATE(TBoycottButton)

  void Select(bool isPressed, bool notifyParent) override;
};

ASSERT_SIZE(TBoycottButton, 0x90);
