#include "game/ui_screens/TGWorldButton.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"

IMPLEMENT_DYNCREATE(TGWorldButton, TControl)

// FUNCTION: IMPERIALISM 0x00572130
TGWorldButton::TGWorldButton() {
  frameOffsetX = 0;
}

// FUNCTION: IMPERIALISM 0x00572190
TGWorldButton::~TGWorldButton() {}

// FUNCTION: IMPERIALISM 0x005721b0
void TGWorldButton::IGWorldButton(TView* panel, int* offsetLayout, int* sizeLayout,
                                  short bitmapResourceId) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  frameSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(bitmapResourceId);
}

// FUNCTION: IMPERIALISM 0x00572200
void TGWorldButton::HiliteState(unsigned char fEnabledState, bool fRefreshNow) {
  if (static_cast<unsigned char>(fEnabledState) == controlState) {
    return;
  }
  controlState = static_cast<unsigned char>(fEnabledState);
  if (fEnabledState == 0) {
    frameOffsetX = static_cast<short>(frameOffsetX - frameWidth);
  } else {
    frameOffsetX = static_cast<short>(frameOffsetX + frameWidth);
  }
  RefreshControl();
  if (fRefreshNow) {
    ForceRedraw();
  }
}

// FUNCTION: IMPERIALISM 0x00572270
void TGWorldButton::Draw(RECT* rectBuffer) {
  if (frameSurface != 0) {
    CRect destRect;
    QueryContentBounds(&destRect);
    RECT srcRect = {frameOffsetX, 0, static_cast<int>(frameOffsetX + frameWidth), frameHeight};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(frameSurface->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &destRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}
