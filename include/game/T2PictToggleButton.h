#pragma once

#include "compat.h"
#include "game/TToggleButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x664470
class T2PictToggleButton : public TToggleButton {
public:
  T2PictToggleButton();
  virtual ~T2PictToggleButton() override;
  CRuntimeClass* GetRuntimeClass() override;

  bool IsSelected(short value = -1, bool refreshNow = true) override; // slot 0x1cc
  void Select(bool isPressed, bool notifyParent) override; // slot 0x1d0
};

ASSERT_SIZE(T2PictToggleButton, 0x90);
