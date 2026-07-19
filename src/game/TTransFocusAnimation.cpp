// TTransFocusAnimation vertical-slice implementations.

#include "game/TTransFocusAnimation.h"

#include "game/global_data_tables.h"
#include "game/CDib.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TView.h"
#include "game/TAnimator.h"
#include "game/TObject.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"
#include "game/bitmap_descriptor_helpers.h"

// SYNTHETIC: IMPERIALISM 0x004a03f0
// TTransFocusAnimation::CreateObject

IMPLEMENT_DYNCREATE(TTransFocusAnimation, TFocusAnimation)

// Default constructor for MFC dynamic creation
TTransFocusAnimation::TTransFocusAnimation() : TFocusAnimation() {
  ownerView04 = nullptr;
  frameIndex08 = 0;
  frameCount0A = 0;
  field0C = 0;
  tickCounter10 = 0;
  ticksPerFrame14 = 0;
  registryTag18 = 0;
  screenRect1C.left = 0;
  screenRect1C.top = 0;
  screenRect1C.right = 0;
  screenRect1C.bottom = 0;
  enabledFlag = 1;
  transientSurfaceContext = 0;
  insetBitmapSurface = 0;
}

// FUNCTION: IMPERIALISM 0x004a04a0
TTransFocusAnimation::TTransFocusAnimation(TView* target, RECT* bounds, short f0a, short f0c,
                                           int tickLimit, int f18)
    : TFocusAnimation() {
  ownerView04 = target;
  frameIndex08 = 0;
  frameCount0A = f0a;
  field0C = f0c;
  tickCounter10 = 0;
  ticksPerFrame14 = tickLimit;
  registryTag18 = f18;
  screenRect1C.left = bounds->left;
  screenRect1C.top = bounds->top;
  screenRect1C.right = bounds->right;
  screenRect1C.bottom = bounds->bottom;
  enabledFlag = 1;
  transientSurfaceContext = 0;
  insetBitmapSurface = 0;

  RECT local_bounds = {0, 0, bounds->right - bounds->left, bounds->bottom - bounds->top};
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&transientSurfaceContext, 8,
                                                         &local_bounds);
  insetBitmapSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(f0c);
}

// SYNTHETIC: IMPERIALISM 0x004a0430
// TTransFocusAnimation::`scalar deleting destructor'
TTransFocusAnimation::~TTransFocusAnimation() {}

// FUNCTION: IMPERIALISM 0x004a0570
void TTransFocusAnimation::Free() {
  if (transientSurfaceContext != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&transientSurfaceContext);
  }
  if (insetBitmapSurface != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&insetBitmapSurface);
  }
  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x004a05c0
void TTransFocusAnimation::BlitTransientSurfaceToPrimaryRenderContextWithClip() {
  CTemporaryRegion surface;
  GetClip(surface.tempRgn);

  RECT destinationRect;
  RECT sourceRect;
  destinationRect.left = 0;
  destinationRect.top = 0;
  sourceRect.left = screenRect1C.left;
  sourceRect.top = screenRect1C.top;
  sourceRect.right = screenRect1C.right;
  destinationRect.right = sourceRect.right - sourceRect.left;
  sourceRect.bottom = screenRect1C.bottom;
  destinationRect.bottom = sourceRect.bottom - sourceRect.top;

  ClipRect(&destinationRect);
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithFallback(0x13);
  SetQuickDrawFillColorFromPaletteIndex(0);

  CDib* primaryDib = g_pPrimaryRenderSurfaceContext->surfaceDib;
  if (primaryDib != 0) {
    int primaryHeight = primaryDib->m_pInfoHeader->bmiHeader.biHeight;
    if (primaryHeight < 1) {
      primaryHeight = -primaryHeight;
    }
    OffsetRect(&sourceRect, 0, (primaryHeight - sourceRect.top) - sourceRect.bottom);
  }

  CDib* transientDib = transientSurfaceContext->surfaceDib;
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
void TTransFocusAnimation::VTableSlot0D() {}

// FUNCTION: IMPERIALISM 0x004a0810
undefined TTransFocusAnimation::RenderBattleReportInsetWithPaletteShift() {
  short width = screenRect1C.right - screenRect1C.left;
  int height = screenRect1C.bottom - screenRect1C.top;

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
  if (animatorTarget->surfaceDib != 0) {
    int animatorTargetHeight = animatorTarget->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (animatorTargetHeight < 1) {
      animatorTargetHeight = -animatorTargetHeight;
    }
    OffsetRect(&clipRect, 0, (animatorTargetHeight - destinationRect.top) - destinationRect.bottom);
  }

  BlitQuickDrawSurfaces(transientSurfaceContext->GetBlitSurface(), animatorTarget->GetBlitSurface(),
                        &destinationRect, &clipRect, 0);

  if (enabledFlag != 0) {
    RECT overlayRect;
    overlayRect.left = frameIndex08 * width;
    overlayRect.right = overlayRect.left + width;
    overlayRect.top = 0;
    overlayRect.bottom = height;
    UpdatePaletteIndexWithFallback(0x10);
    BlitQuickDrawSurfaces(insetBitmapSurface->GetBlitSurface(), animatorTarget->GetBlitSurface(),
                          &overlayRect, &clipRect, 0x24);
  }

  FocusAnimationSlot0E();

  TQuickDrawSurfaceContext* activeContext;
  int activeFlags;
  GetActiveQuickDrawSurfaceContextAndFlags(&activeContext, &activeFlags);
  SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, activeFlags);
  FocusAnimationSlot0E();
  SetActiveQuickDrawSurfaceContext(activeContext, activeFlags);

  return 0;
}
