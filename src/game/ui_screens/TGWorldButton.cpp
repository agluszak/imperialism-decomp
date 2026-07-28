#include "game/ui_screens/TGWorldButton.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"

// SYNTHETIC: IMPERIALISM 0x00572080
// TGWorldButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00572110
// TGWorldButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGWorldButton, TControl)

// FUNCTION: IMPERIALISM 0x00572130
TGWorldButton::TGWorldButton() {
  field84 = 0;
}

// SYNTHETIC: IMPERIALISM 0x00572160
// TGWorldButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00572190
TGWorldButton::~TGWorldButton() {}

// FUNCTION: IMPERIALISM 0x005721b0
void TGWorldButton::IGWorldButton(TView* panel, int* offsetLayout, int* sizeLayout,
                                  short bitmapResourceId) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 4, 4, 0);
  field88 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(bitmapResourceId);
}

// FUNCTION: IMPERIALISM 0x00572200
void TGWorldButton::HiliteState(unsigned char fEnabledState, unsigned char fRefreshNow) {
  if (static_cast<unsigned char>(fEnabledState) == controlState64) {
    return;
  }
  controlState64 = static_cast<unsigned char>(fEnabledState);
  if (fEnabledState == 0) {
    field84 = static_cast<short>(field84 - frameWidth34);
  } else {
    field84 = static_cast<short>(field84 + frameWidth34);
  }
  RefreshControl();
  if (fRefreshNow) {
    ForceRedraw();
  }
}

// FUNCTION: IMPERIALISM 0x00572270
void TGWorldButton::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  if (field88 != 0) {
    CRect destRect;
    QueryContentBounds(&destRect);
    RECT srcRect = {field84, 0, static_cast<int>(field84 + frameWidth34), frameHeight38};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(field88->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &destRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}
