#pragma once

#include "compat.h"

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006646a8
class TCloseButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TCloseButton)
  virtual ~TCloseButton() override;
  virtual bool HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;

  TCloseButton();
};
ASSERT_SIZE(TCloseButton, 0x94);
