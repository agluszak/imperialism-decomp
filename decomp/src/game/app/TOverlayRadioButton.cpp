#include "game/app/TOverlayRadioButton.h"

#include "game/ui_core/TPicture.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TOverlayRadioButton, TRadioPictureButton)

// FUNCTION: IMPERIALISM 0x00453800
TOverlayRadioButton::TOverlayRadioButton() {
  overlaySurfaceContext = 0;
}

// FUNCTION: IMPERIALISM 0x00453860
TOverlayRadioButton::~TOverlayRadioButton() {}

// FUNCTION: IMPERIALISM 0x004cab10
void TOverlayRadioButton::Draw(RECT* rectBuffer) {
  TPicture::Draw(rectBuffer);
  if (overlaySurfaceContext != 0) {
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(overlaySurfaceContext->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                     &overlaySrcRect, &overlayDstRect, 0x24);
    SetQuickDrawStrokeColor(0x13);
  }
}
