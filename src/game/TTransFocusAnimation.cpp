// TTransFocusAnimation vertical-slice implementations.

#include "game/TTransFocusAnimation.h"

#include "game/global_data_tables.h"
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

void WrapperFor_FreeHeapBufferIfNotNull_At004feb50(int* field);
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);

// Default constructor for MFC dynamic creation
TTransFocusAnimation::TTransFocusAnimation()
    : TFocusAnimation() {
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
  field34 = 0;
}

// FUNCTION: IMPERIALISM 0x004a04a0
TTransFocusAnimation::TTransFocusAnimation(void* target, RECT* bounds, short f0a, short f0c, int tickLimit, int f18)
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
  field34 = 0;

  RECT local_bounds = {0, 0, bounds->right - bounds->left, bounds->bottom - bounds->top};
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&transientSurfaceContext, 8, &local_bounds);
  field34 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(f0c);
}

// SYNTHETIC: IMPERIALISM 0x004a0430
// TTransFocusAnimation::`scalar deleting destructor'
TTransFocusAnimation::~TTransFocusAnimation() {}

// FUNCTION: IMPERIALISM 0x004a0570
void TTransFocusAnimation::Free() {
  if (transientSurfaceContext != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(&transientSurfaceContext);
  }
  if (field34 != 0) {
    WrapperFor_FreeHeapBufferIfNotNull_At004feb50(&field34);
  }
  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x004a0770
void TTransFocusAnimation::VTableSlot0D(int* completionRecord) {
  (void)completionRecord;
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
  UpdatePaletteIndexWithDefaultFallback();
  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(0);

  int primaryFlipDescriptor = g_pPrimaryRenderSurfaceContext->flipDescriptor;
  if (primaryFlipDescriptor != 0) {
    int primaryFlipHeight =
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(primaryFlipDescriptor + 0x10) + 8);
    if (primaryFlipHeight < 1) {
      primaryFlipHeight = -primaryFlipHeight;
    }
    OffsetRect(&sourceRect, 0, (primaryFlipHeight - sourceRect.top) - sourceRect.bottom);
  }

  int transientContext = transientSurfaceContext;
  int transientFlipDescriptor = *reinterpret_cast<int*>(transientContext + 0x20);
  if (transientFlipDescriptor != 0) {
    int transientFlipHeight =
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(transientFlipDescriptor + 0x10) + 8);
    if (transientFlipHeight < 1) {
      transientFlipHeight = -transientFlipHeight;
    }
    OffsetRect(&destinationRect, 0,
               (transientFlipHeight - destinationRect.top) - destinationRect.bottom);
  }

  BlitQuickDrawSurfaces(
      g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
      reinterpret_cast<TQuickDrawSurfaceContext*>(transientContext)->GetBlitSurface(), &sourceRect,
      &destinationRect, 0);
  SnapshotHitRegionToClipCache(reinterpret_cast<int*>(surface.surfaceWrapper));
}

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

  RECT clipRect = destinationRect;
  int uiAnimatorFlipDescriptor = *reinterpret_cast<int*>(g_pUiAnimator + 0x20);
  if (uiAnimatorFlipDescriptor != 0) {
    int uiAnimatorFlipHeight =
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(uiAnimatorFlipDescriptor + 0x10) + 8);
    if (uiAnimatorFlipHeight < 1) {
      uiAnimatorFlipHeight = -uiAnimatorFlipHeight;
    }
    OffsetRect(&clipRect, 0, (uiAnimatorFlipHeight - destinationRect.top) - destinationRect.bottom);
  }

  int uiAnimatorBlitSurface = uiAnimatorFlipDescriptor + 4;
  BlitQuickDrawSurfaces(
      reinterpret_cast<TQuickDrawBlitSurface*>(transientSurfaceContext + 4),
      reinterpret_cast<TQuickDrawBlitSurface*>(uiAnimatorBlitSurface),
      &destinationRect, &clipRect, 0);

  if (enabledFlag != 0) {
    RECT overlayRect;
    overlayRect.left = Field08() * width;
    overlayRect.right = overlayRect.left + width;
    overlayRect.top = 0;
    overlayRect.bottom = height;
    UpdatePaletteIndexWithDefaultFallback();
    BlitQuickDrawSurfaces(
        reinterpret_cast<TQuickDrawBlitSurface*>(field34 + 4),
        reinterpret_cast<TQuickDrawBlitSurface*>(uiAnimatorBlitSurface),
        &overlayRect, &clipRect, 0x24);
  }

  Helper_Uses_BlitRectWithOptionalTransparency_At004a0280();

  undefined4 activeContext;
  int activeFlags;
  GetActiveQuickDrawSurfaceContextAndFlags(&activeContext, &activeFlags);
  SetActiveQuickDrawSurfaceContext(reinterpret_cast<int>(g_pPrimaryRenderSurfaceContext), activeFlags);
  Helper_Uses_BlitRectWithOptionalTransparency_At004a0280();
  SetActiveQuickDrawSurfaceContext(activeContext, activeFlags);

  return 0;
}
