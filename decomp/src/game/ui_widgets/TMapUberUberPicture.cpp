#include "game/ui_widgets/TMapUberUberPicture.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x0045d270
TMapUberUberPicture::TMapUberUberPicture() : TOffLimitsPicture() {}

// FUNCTION: IMPERIALISM 0x0045d2a0
void TMapUberUberPicture::Scroll(MapScrollEdgeMaskStorage edgeMask) {}

// FUNCTION: IMPERIALISM 0x0045d2f0
TMapUberUberPicture::~TMapUberUberPicture() {}

IMPLEMENT_DYNCREATE(TMapUberUberPicture, TOffLimitsPicture)

// FUNCTION: IMPERIALISM 0x00596810
void TMapUberUberPicture::DoPostCreate(int arg) {
  TOffLimitsPicture::DoPostCreate(arg);
  g_pAmbitApplication->edgeScrollTarget = this;
}

// FUNCTION: IMPERIALISM 0x00596840
void TMapUberUberPicture::Free() {
  g_pAmbitApplication->edgeScrollTarget = 0;
  g_pAmbitApplication->cursorRegionInvalid = FALSE;
  TOffLimitsPicture::Free();
}
