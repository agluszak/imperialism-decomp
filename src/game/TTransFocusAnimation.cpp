// TTransFocusAnimation vertical-slice implementations.

#include "game/TTransFocusAnimation.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/TView.h"
#include "game/mfc.h"
#include "game/quickdraw_globals.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"

// This QuickDraw body keeps the EH-RAII frame but omits the frame pointer.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 ApplyHitRegionToClipState(void);
undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);

// FUNCTION: IMPERIALISM 0x004a05c0
void TTransFocusAnimation::BlitTransientSurfaceToPrimaryRenderContextWithClip() {
  QuickDrawSurfaceGuard surface;
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  RECT destinationRect;
  RECT sourceRect;
  destinationRect.left = 0;
  destinationRect.top = 0;
  sourceRect.left = sourceLeft;
  sourceRect.top = sourceTop;
  sourceRect.right = sourceRight;
  destinationRect.right = sourceRect.right - sourceRect.left;
  sourceRect.bottom = sourceBottom;
  destinationRect.bottom = sourceRect.bottom - sourceRect.top;

  reinterpret_cast<void(__cdecl*)(RECT*)>(thunk_ApplyRectClipRegionToGlobalClipState)(
      &destinationRect);
  ResetQuickDrawStrokeState();
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(0);

  int(__stdcall * offsetRect)(RECT*, int, int) = OffsetRect;
  int primaryFlipDescriptor = g_pPrimaryRenderSurfaceContext->flipDescriptor;
  if (primaryFlipDescriptor != 0) {
    int primaryFlipHeight =
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(primaryFlipDescriptor + 0x10) + 8);
    if (primaryFlipHeight < 1) {
      primaryFlipHeight = -primaryFlipHeight;
    }
    offsetRect(&sourceRect, 0, (primaryFlipHeight - sourceRect.top) - sourceRect.bottom);
  }

  int transientContext = transientSurfaceContext;
  int transientFlipDescriptor = *reinterpret_cast<int*>(transientContext + 0x20);
  if (transientFlipDescriptor != 0) {
    int transientFlipHeight =
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(transientFlipDescriptor + 0x10) + 8);
    if (transientFlipHeight < 1) {
      transientFlipHeight = -transientFlipHeight;
    }
    offsetRect(&destinationRect, 0,
               (transientFlipHeight - destinationRect.top) - destinationRect.bottom);
  }

  BlitQuickDrawSurfaces(
      g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
      reinterpret_cast<TQuickDrawSurfaceContext*>(transientContext)->GetBlitSurface(), &sourceRect,
      &destinationRect, 0);
  reinterpret_cast<void(__cdecl*)(int)>(SnapshotHitRegionToClipCache)(surface.surfaceWrapper);
}

// FUNCTION: IMPERIALISM 0x004a0770
void TTransFocusAnimation::RenderFocusAnimationFrameWithScopedQuickDraw() {
  ScopedMapQuickDrawContextGuard quickDrawContext(scopedRenderTarget);
  reinterpret_cast<TView*>(scopedRenderTarget)->Refresh();

  int completionRecord[2];
  completionRecord[0] = 0;
  completionRecord[1] = 0;
  this->DispatchCompletionRecordSlot14(completionRecord);
}
