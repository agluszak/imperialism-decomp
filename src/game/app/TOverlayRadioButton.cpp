#include "game/TOverlayRadioButton.h"

#include "game/TPicture.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004caa50
// TOverlayRadioButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x004caaf0
// TOverlayRadioButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOverlayRadioButton, TRadioPictureButton)

// FUNCTION: IMPERIALISM 0x00453800
TOverlayRadioButton::TOverlayRadioButton() : TRadioPictureButton() {
  overlaySurfaceContext98 = 0;
}

// SYNTHETIC: IMPERIALISM 0x00453830
// TOverlayRadioButton::`scalar deleting destructor'
TOverlayRadioButton::~TOverlayRadioButton() {}

// slot 0x44 — Draw override: base picture render, then blit the attached
// overlay surface into the active quickdraw surface.
// FUNCTION: IMPERIALISM 0x004cab10
void TOverlayRadioButton::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  if (overlaySurfaceContext98 != 0) {
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitQuickDrawSurfaces(overlaySurfaceContext98->GetBlitSurface(),
                          g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &overlaySrcRect9c,
                          &overlayDstRectAc, 0x24);
    SetQuickDrawStrokeColor(0x13);
  }
}
