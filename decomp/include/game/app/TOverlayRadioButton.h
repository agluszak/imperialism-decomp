#pragma once

#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TRadioPictureButton.h"

// VTABLE: IMPERIALISM 0x00643a40
class TOverlayRadioButton : public TRadioPictureButton {
public:
  DECLARE_DYNCREATE(TOverlayRadioButton)

  TOverlayRadioButton();
  virtual ~TOverlayRadioButton() override; // slot 0x01 (scalar deleting destructor 0x453830)

  void Draw(RECT* rectBuffer) override; // slot 0x44 0x4cab10

  TQuickDrawSurfaceContext* overlaySurfaceContext; // +0x98 — 0 when no overlay attached
  RECT overlaySrcRect;                             // +0x9c
  RECT overlayDstRect;                             // +0xac
};

ASSERT_SIZE(TOverlayRadioButton, 0xbc);
