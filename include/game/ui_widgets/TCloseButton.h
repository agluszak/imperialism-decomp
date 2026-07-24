#pragma once

#include "compat.h"

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006646a8
class TCloseButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TCloseButton)
  virtual ~TCloseButton() override; // slot 0x01 (scalar deleting destructor)
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                               CPoint origin) override; // slot 0x46 0x584b70

  TCloseButton();
};
ASSERT_SIZE(TCloseButton, 0x94);
