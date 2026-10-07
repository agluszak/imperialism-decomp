#include "game/ui_screens/TMegaPicture.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/TBitmapResourceLoader.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"

IMPLEMENT_DYNCREATE(TMegaPicture, TNoHilitePicture)

// FUNCTION: IMPERIALISM 0x00573190
TMegaPicture::TMegaPicture() {
  surfaceContext = 0;
  modeFlags = 0;
}

// FUNCTION: IMPERIALISM 0x00573200
TMegaPicture::~TMegaPicture() {}

// FUNCTION: IMPERIALISM 0x00573220
void TMegaPicture::IMegaPicture(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                                int layoutParam5, short pictureId, unsigned short flags) {
  IPicture(panel, offsetLayout, sizeLayout, layoutParam4, layoutParam5, pictureId);
  SetMode(flags, false);
}

// FUNCTION: IMPERIALISM 0x00573270
void TMegaPicture::Draw(RECT* rectBuffer) {
  CRect contentRect(*rectBuffer);
  CRect screenRect = ViewToQDRect(&contentRect);
  if (surfaceContext == NULL) {
    return;
  }
  ResetQuickDrawStrokeState();

  RECT srcRect;
  if ((modeFlags & 4) == 0) {
    srcRect = *rectBuffer;
  } else {
    if ((modeFlags & 1) == 0) {
      SetQuickDrawFillColor(0xffffff);
      FillRectWithQuickDrawBrushAndContextOffset(&screenRect);
    }
    srcRect = contentSubRect;
    screenRect = ViewToQDRect(&contentSubRect);
  }

  unsigned char blitFlags = 0;
  QuickDrawPaletteIndex paletteIndex = 0x13;
  if (modeFlags & 1) {
    blitFlags = 0x24;
    paletteIndex = 0x10;
  }
  UpdatePaletteIndexWithDefaultFallback(paletteIndex);
  SetQuickDrawFillColor(0);
  BlitRectWithOptionalTransparency(surfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &screenRect, blitFlags, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x00573430
void TMegaPicture::SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow) {
  if (surfaceContext != 0) {
    g_pDisplayMgr->RemoveGWorld(surfaceContext);
  }
  surfaceContext = 0;
  ReleasePicture();

  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(nPictureId);
  QDLoadResource(loaderHandle);
  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader == 0) {
    return;
  }
  RECT resourceBounds;
  CopyRect(&resourceBounds, &loader->bitmapRect);
  contentSubRect = resourceBounds;

  TQuickDrawSurfaceContext* savedContext = 0;
  int savedFlags = 0;
  GetGWorld(&savedContext, &savedFlags);
  g_pDisplayMgr->MakeNewGWorld(surfaceContext, 8, resourceBounds);
  SetGWorld(surfaceContext, savedFlags);
  TBitmapSurfaceNode** pixMap = GetGWorldPixMap(surfaceContext);
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
    IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
    delete *loaderHandle;
    IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
    delete loaderHandle;
    UnlockPixels(GetGWorldPixMap(surfaceContext));
    SetGWorld(savedContext, savedFlags);
    TPicture::SetPictureRsrcID(nPictureId, fRefreshNow);
  }
}

// FUNCTION: IMPERIALISM 0x00573650
void TMegaPicture::Free() {
  if (surfaceContext != 0) {
    g_pDisplayMgr->RemoveGWorld(surfaceContext);
  }
  surfaceContext = 0;
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x00573690
void TMegaPicture::SetMode(unsigned short value, bool refreshNow) {
  modeFlags = value;
  if (refreshNow) {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x005736c0
void TMegaPicture::ClearModeBits(unsigned short mask, char useAndMask, char refreshNow) {
  if (useAndMask) {
    modeFlags &= mask;
  } else {
    modeFlags -= mask;
  }
  if (refreshNow) {
    RefreshControl();
  }
}
