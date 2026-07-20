#include "game/TMegaPicture.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x005730d0
// TMegaPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00573170
// TMegaPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMegaPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00573190
TMegaPicture::TMegaPicture() {}

// SYNTHETIC: IMPERIALISM 0x005731d0
// TMegaPicture::`scalar deleting destructor'
TMegaPicture::~TMegaPicture() {}

// Blits the picture's own bitmap to its transformed (screen-space) rect. Normally
// samples the whole passed-in rect; when flags98&4 is set, samples/positions from
// contentSubRect9c instead (optionally filling the transformed rect white first when
// flags98&1 is clear), and applies transparent-color blitting (flags98&1).
// FUNCTION: IMPERIALISM 0x00573270
void TMegaPicture::ApplyRectSlot110(RECT* rectBuffer) {
  RECT screenRect = TransformRectViaSlot148(rectBuffer);
  if (surfaceContext94 == nullptr) {
    return;
  }
  ResetQuickDrawStrokeState();

  RECT srcRect;
  if ((flags98 & 4) == 0) {
    srcRect = *rectBuffer;
  } else {
    if ((flags98 & 1) == 0) {
      SetQuickDrawFillColor(0xffffff);
      FillRectWithQuickDrawBrushAndContextOffset(&screenRect);
    }
    srcRect = contentSubRect9c;
    screenRect = TransformRectViaSlot148(&contentSubRect9c);
  }

  unsigned char blitFlags = 0;
  int paletteIndex = 0x13;
  if (flags98 & 1) {
    blitFlags = 0x24;
    paletteIndex = 0x10;
  }
  UpdatePaletteIndexWithDefaultFallback(paletteIndex);
  SetQuickDrawFillColor(0);
  BlitRectWithOptionalTransparency(surfaceContext94->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &screenRect, blitFlags, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00573430
void TMegaPicture::SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) {}

// FUNCTION: IMPERIALISM 0x00573650
void TMegaPicture::Free() {}

// FUNCTION: IMPERIALISM 0x00573690
void TMegaPicture::AssignFlags98AndMaybeRefresh(unsigned short value, char refreshNow) {
  flags98 = value;
  if (refreshNow) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005736c0
void TMegaPicture::ClearOrSubtractFlags98AndMaybeRefresh(unsigned short mask, char useAndMask,
                                                         char refreshNow) {
  if (useAndMask) {
    flags98 &= mask;
  } else {
    flags98 -= mask;
  }
  if (refreshNow) {
    RefreshControl();
  }
}
