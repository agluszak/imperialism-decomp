#pragma once

#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TRadioPictureButton.h"

// VTABLE: IMPERIALISM 0x00643a40
class TOverlayRadioButton : public TRadioPictureButton {
public:
  DECLARE_DYNCREATE(TOverlayRadioButton)

  TOverlayRadioButton();
  virtual ~TOverlayRadioButton() override;

  void Draw(RECT* rectBuffer) override;

  TQuickDrawSurfaceContext* overlaySurfaceContext; // 0 when no overlay attached
  RECT overlaySrcRect;
  RECT overlayDstRect;
};

ASSERT_SIZE(TOverlayRadioButton, 0xbc);
