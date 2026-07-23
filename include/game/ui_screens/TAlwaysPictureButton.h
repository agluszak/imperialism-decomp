#pragma once

#include "compat.h"
#include "game/ui_screens/TPictureButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65e928
class TAlwaysPictureButton : public TPictureButton {
public:
  virtual ~TAlwaysPictureButton() override; // slot 0x01 (scalar deleting destructor)
  TAlwaysPictureButton();
  DECLARE_DYNCREATE(TAlwaysPictureButton)
  void HiliteState(unsigned char enabledState, unsigned char refreshNow) override;
  virtual void Select(bool isPressed, bool notifyParent); // slot 0x1d0
};

ASSERT_SIZE(TAlwaysPictureButton, 0x94);
