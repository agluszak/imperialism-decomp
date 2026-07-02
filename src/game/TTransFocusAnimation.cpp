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

IMPLEMENT_DYNCREATE(TTransFocusAnimation, TFocusAnimation)

undefined4 SetQuickDrawFillColorFromPaletteIndex(void);

// Default constructor for MFC dynamic creation
TTransFocusAnimation::TTransFocusAnimation() : TFocusAnimation() {
  ScopedRenderTarget() = nullptr;
  Field08() = 0;
  Field0a() = 0;
  Field0c() = 0;
  FrameTick() = 0;
  FrameTickLimit() = 0;
  Field18() = 0;
  SourceLeft() = 0;
  SourceTop() = 0;
  SourceRight() = 0;
  SourceBottom() = 0;
  enabledFlag = 1;
  transientSurfaceContext = 0;
  insetBitmapSurface = 0;
}

// FUNCTION: IMPERIALISM 0x004a04a0
TTransFocusAnimation::TTransFocusAnimation(TView* target, RECT* bounds, short f0a, short f0c,
                                           int tickLimit, int f18)
    : TFocusAnimation() {
  ScopedRenderTarget() = target;
  Field08() = 0;
  Field0a() = f0a;
  Field0c() = f0c;
  FrameTick() = 0;
  FrameTickLimit() = tickLimit;
  Field18() = f18;
  SourceLeft() = bounds->left;
  SourceTop() = bounds->top;
  SourceRight() = bounds->right;
  SourceBottom() = bounds->bottom;
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
    FreeQuickDrawSurfaceContextSlot(&transientSurfaceContext);
  }
  if (insetBitmapSurface != 0) {
    FreeQuickDrawSurfaceContextSlot(&insetBitmapSurface);
  }
  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x004a05c0
void TTransFocusAnimation::BlitTransientSurfaceToPrimaryRenderContextWithClip() {
  QuickDrawSurfaceGuard surface;
  ApplyHitRegionToClipState();

  RECT destinationRect;
  RECT sourceRect;
  destinationRect.left = 0;
  destinationRect.top = 0;
  sourceRect.left = SourceLeft();
  sourceRect.top = SourceTop();
  sourceRect.right = SourceRight();
  destinationRect.right = sourceRect.right - sourceRect.left;
  sourceRect.bottom = SourceBottom();
  destinationRect.bottom = sourceRect.bottom - sourceRect.top;

  ApplyRectClipRegionToGlobalClipState();
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithFallback(0x13);
  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(0);

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
  SnapshotHitRegionToClipCache(reinterpret_cast<int*>(surface.surfaceWrapper));
}

// FUNCTION: IMPERIALISM 0x004a0770
void TTransFocusAnimation::VTableSlot0D() {}

// FUNCTION: IMPERIALISM 0x004a0810
undefined TTransFocusAnimation::RenderBattleReportInsetWithPaletteShift() {
  short width = SourceRight() - SourceLeft();
  int height = SourceBottom() - SourceTop();

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
    overlayRect.left = Field08() * width;
    overlayRect.right = overlayRect.left + width;
    overlayRect.top = 0;
    overlayRect.bottom = height;
    UpdatePaletteIndexWithFallback(0x10);
    BlitQuickDrawSurfaces(insetBitmapSurface->GetBlitSurface(), animatorTarget->GetBlitSurface(),
                          &overlayRect, &clipRect, 0x24);
  }

  Helper_Uses_BlitRectWithOptionalTransparency_At004a0280();

  TQuickDrawSurfaceContext* activeContext;
  int activeFlags;
  GetActiveQuickDrawSurfaceContextAndFlags(&activeContext, &activeFlags);
  SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, activeFlags);
  Helper_Uses_BlitRectWithOptionalTransparency_At004a0280();
  SetActiveQuickDrawSurfaceContext(activeContext, activeFlags);

  return 0;
}
