#include "game/ui_screens/TMegaPicture.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/TBitmapResourceLoader.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
// SYNTHETIC: IMPERIALISM 0x005730d0
// TMegaPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00573170
// TMegaPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMegaPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00573190
TMegaPicture::TMegaPicture() : TNoHilitePicture() {
  surfaceContext94 = 0;
  flags98 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005731d0
// TMegaPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00573200
TMegaPicture::~TMegaPicture() {}

// Blits the picture's own bitmap to its transformed (screen-space) rect. Normally
// samples the whole passed-in rect; when flags98&4 is set, samples/positions from
// contentSubRect9c instead (optionally filling the transformed rect white first when
// flags98&1 is clear), and applies transparent-color blitting (flags98&1).
// FUNCTION: IMPERIALISM 0x00573270
void TMegaPicture::Draw(RECT* rectBuffer) {
  CRect contentRect(*rectBuffer);
  CRect screenRect = ViewToQDRect(&contentRect);
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
    screenRect = ViewToQDRect(&contentSubRect9c);
  }

  unsigned char blitFlags = 0;
  QuickDrawPaletteIndex paletteIndex = 0x13;
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

// Rebuilds the picture's private offscreen surface from bitmap resource `nPictureId`:
// dispose any previous surface, create a fresh 8-bit GWorld sized to the resource
// bounds, blit the resource into it, then run the base TPicture refresh.
// FUNCTION: IMPERIALISM 0x00573430
void TMegaPicture::SetPictureResourceIdAndRefresh(short nPictureId, unsigned char fRefreshNow) {
  if (surfaceContext94 != 0) {
    g_pDisplayMgr->RemoveGWorld(surfaceContext94);
  }
  surfaceContext94 = 0;
  ResetPictureResourceEntry();

  // The original parks the loader handle in the +0x88 slot (TPicture::bitmapId/
  // resourceNamespaceId) until the trailing base call overwrites it with the real
  // packed id; modeled as a local instead of punning the shorts.
  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(nPictureId);
  QDLoadResource(loaderHandle);
  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader == 0) {
    return;
  }
  RECT resourceBounds;
  CopyRect(&resourceBounds, &loader->bitmapRect);
  contentSubRect9c = resourceBounds;

  TQuickDrawSurfaceContext* savedContext = 0;
  int savedFlags = 0;
  GetGWorld(&savedContext, &savedFlags);
  g_pDisplayMgr->MakeNewGWorld(surfaceContext94, 8, resourceBounds);
  SetGWorld(surfaceContext94, savedFlags);
  TBitmapSurfaceNode** pixMap = GetGWorldPixMap(surfaceContext94);
  LockPixels(pixMap);

  QDLoadResource(loaderHandle);
  loader = *loaderHandle;
  if (loader != 0) {
    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    ResetQuickDrawStrokeState();
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, &resourceBounds);
    loader = *loaderHandle;
    loader->ReleaseBitmapResource();
    loader->flags &= 0xfe;
    delete *loaderHandle;
    delete loaderHandle;
    UnlockPixels(GetGWorldPixMap(surfaceContext94));
    SetGWorld(savedContext, savedFlags);
    TPicture::SetPictureResourceIdAndRefresh(nPictureId, fRefreshNow);
  }
}

// FUNCTION: IMPERIALISM 0x00573650
void TMegaPicture::Free() {
  if (surfaceContext94 != 0) {
    g_pDisplayMgr->RemoveGWorld(surfaceContext94);
  }
  surfaceContext94 = 0;
  TView::Free();
}

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
