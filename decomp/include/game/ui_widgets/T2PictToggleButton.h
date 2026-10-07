#pragma once

#include "compat.h"
#include "game/ui_screens/TToggleButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x664470
class T2PictToggleButton : public TToggleButton {
public:
  T2PictToggleButton();
  virtual ~T2PictToggleButton() override;
  DECLARE_DYNCREATE(T2PictToggleButton)
  bool IsSelected() override;
  void Select(bool isPressed, bool notifyParent) override;
};

ASSERT_SIZE(T2PictToggleButton, 0x90);
