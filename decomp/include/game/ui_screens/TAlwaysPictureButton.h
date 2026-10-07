#pragma once

#include "compat.h"
#include "game/ui_screens/TPictureButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65e928
class TAlwaysPictureButton : public TPictureButton {
public:
  virtual ~TAlwaysPictureButton() override;
  TAlwaysPictureButton();
  DECLARE_DYNCREATE(TAlwaysPictureButton)
  void HiliteState(unsigned char enabledState, bool refreshNow) override;
  virtual void Select(bool isPressed, bool notifyParent);
};

ASSERT_SIZE(TAlwaysPictureButton, 0x94);
