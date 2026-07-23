#pragma once

#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TRadioPictureButton.h"

// Radio picture button that blits an extra overlay surface over the base picture when
// one is attached. Adds the overlay surface context and its source/destination rects.
// RTTI: classTOverlayRadioButton @ 0x006512a8, base TRadioPictureButton.
// VTABLE: IMPERIALISM 0x00643a40
class TOverlayRadioButton : public TRadioPictureButton {
public:
  DECLARE_DYNCREATE(TOverlayRadioButton)

  TOverlayRadioButton();
  virtual ~TOverlayRadioButton() override; // slot 0x01 (scalar deleting destructor 0x453830)

  void Draw(RECT* rectBuffer) override; // slot 0x44 0x4cab10

  TQuickDrawSurfaceContext* overlaySurfaceContext98; // +0x98 — 0 when no overlay attached
  RECT overlaySrcRect9c;                             // +0x9c
  RECT overlayDstRectAc;                             // +0xac
};

ASSERT_SIZE(TOverlayRadioButton, 0xbc);
