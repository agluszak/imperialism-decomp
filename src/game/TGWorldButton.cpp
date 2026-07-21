#include "game/TGWorldButton.h"

#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"

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
TGWorldButton::~TGWorldButton() {}

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
    InvokeSlot13C();
  }
}

// FUNCTION: IMPERIALISM 0x00572270
void TGWorldButton::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  if (field88 != 0) {
    RECT destRect;
    QueryContentBounds(&destRect);
    RECT srcRect = {field84, 0, static_cast<int>(field84 + frameWidth34), frameHeight38};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(field88->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &destRect, 0x24, 0);
    UpdatePaletteIndexWithDefaultFallback(0x13);
  }
}
