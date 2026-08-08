#pragma once

#include "compat.h"
#include "game/mfc.h"
#include "game/ui_screens/TPictureButton.h"

// VTABLE: IMPERIALISM 0x665608
class TClosePicture : public TPictureButton {
public:
  TClosePicture();
  virtual ~TClosePicture() override;

  DECLARE_DYNCREATE(TClosePicture)
  virtual char HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
};

ASSERT_SIZE(TClosePicture, 0x94);
