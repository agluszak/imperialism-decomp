// TTransFocusAnimation vertical-slice implementations.

#include "game/app/TTransFocusAnimation.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/CDib.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/app/TAnimator.h"
#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"

// SYNTHETIC: IMPERIALISM 0x004a03f0
// TTransFocusAnimation::CreateObject

IMPLEMENT_DYNCREATE(TTransFocusAnimation, TFocusAnimation)

// SYNTHETIC: IMPERIALISM 0x004a0430
// TTransFocusAnimation::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x004a0480
// TTransFocusAnimation::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x004a04a0
TTransFocusAnimation::TTransFocusAnimation(TView* target, RECT* bounds, short f0a, short f0c,
                                           int tickLimit, int f18)
    : TFocusAnimation() {
  ownerView = target;
  frameIndex = 0;
  frameCount = f0a;
  frameResourceBaseId = f0c;
  ticksSinceFrameChange = 0;
  ticksPerFrame = tickLimit;
  registryTag = f18;
  screenRect.left = bounds->left;
  screenRect.top = bounds->top;
  screenRect.right = bounds->right;
  screenRect.bottom = bounds->bottom;
  enabledFlag = 1;
  transientSurfaceContext = 0;
  insetBitmapSurface = 0;

  RECT local_bounds = {0, 0, bounds->right - bounds->left, bounds->bottom - bounds->top};
  g_pDisplayMgr->MakeNewGWorld(transientSurfaceContext, 8, local_bounds);
  insetBitmapSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(f0c);
}

// FUNCTION: IMPERIALISM 0x004a0570
void TTransFocusAnimation::Free() {
  if (transientSurfaceContext != 0) {
    g_pDisplayMgr->RemoveGWorld(transientSurfaceContext);
  }
  if (insetBitmapSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(insetBitmapSurface);
  }
  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x004a05c0
void TTransFocusAnimation::UpdateBackground() {
  CTemporaryRegion surface;
  GetClip(surface.tempRgn);

  RECT destinationRect;
  RECT sourceRect;
  destinationRect.left = 0;
  destinationRect.top = 0;
  sourceRect.left = screenRect.left;
  sourceRect.top = screenRect.top;
  sourceRect.right = screenRect.right;
  destinationRect.right = sourceRect.right - sourceRect.left;
  sourceRect.bottom = screenRect.bottom;
  destinationRect.bottom = sourceRect.bottom - sourceRect.top;

  ClipRect(&destinationRect);
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x13);
  SetQuickDrawFillColorFromPaletteIndex(0);

  CDib* primaryDib = g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib;
  if (primaryDib != 0) {
    int primaryHeight = primaryDib->m_pInfoHeader->bmiHeader.biHeight;
    if (primaryHeight < 1) {
      primaryHeight = -primaryHeight;
    }
    OffsetRect(&sourceRect, 0, (primaryHeight - sourceRect.top) - sourceRect.bottom);
  }

  CDib* transientDib = transientSurfaceContext->blitSurface.surfaceDib;
  if (transientDib != 0) {
    int transientHeight = transientDib->m_pInfoHeader->bmiHeader.biHeight;
    if (transientHeight < 1) {
      transientHeight = -transientHeight;
    }
    OffsetRect(&destinationRect, 0,
               (transientHeight - destinationRect.top) - destinationRect.bottom);
  }

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        transientSurfaceContext->GetBlitSurface(), &sourceRect, &destinationRect,
                        0);
  SetClip(surface.tempRgn);
}

// FUNCTION: IMPERIALISM 0x004a0770
void TTransFocusAnimation::IdleDraw() {
  ScopedMapQuickDrawContext guard(ownerView);
  ownerView->PrepareForDrawing();
  POINT offset = {0, 0};
  DrawNextFrame(&offset);
}

// FUNCTION: IMPERIALISM 0x004a0810
void TTransFocusAnimation::DrawNextFrame(POINT* offset) {
  short width = screenRect.right - screenRect.left;
  int height = screenRect.bottom - screenRect.top;

  RECT destinationRect;
  destinationRect.left = 0;
  destinationRect.top = 0;
  destinationRect.right = width;
  destinationRect.bottom = height;

  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);
  SetQuickDrawFillColor(0);

  // Original (0x4a0810): the blit target is the surface context held at
  // g_pUiAnimator+0x20; the height check reads that context's backing dib. The
  // previous port collapsed both dereferences into one and applied pointer
  // arithmetic to the TAnimator*, reading a garbage "context".
  RECT clipRect = destinationRect;
  TQuickDrawSurfaceContext* animatorTarget = g_pUiAnimator->renderSurfaceContext;
  if (animatorTarget->blitSurface.surfaceDib != 0) {
    int animatorTargetHeight =
        animatorTarget->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (animatorTargetHeight < 1) {
      animatorTargetHeight = -animatorTargetHeight;
    }
    OffsetRect(&clipRect, 0, (animatorTargetHeight - destinationRect.top) - destinationRect.bottom);
  }

  BlitQuickDrawSurfaces(transientSurfaceContext->GetBlitSurface(), animatorTarget->GetBlitSurface(),
                        &destinationRect, &clipRect, 0);

  if (enabledFlag != 0) {
    RECT overlayRect;
    overlayRect.left = frameIndex * width;
    overlayRect.right = overlayRect.left + width;
    overlayRect.top = 0;
    overlayRect.bottom = height;
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitQuickDrawSurfaces(insetBitmapSurface->GetBlitSurface(), animatorTarget->GetBlitSurface(),
                          &overlayRect, &clipRect, 0x24);
  }

  ClipAndPaste();

  TQuickDrawSurfaceContext* activeContext;
  int activeFlags;
  GetGWorld(&activeContext, &activeFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, activeFlags);
  ClipAndPaste();
  SetGWorld(activeContext, activeFlags);
}
