// TTransFocusAnimation vertical-slice implementations.

#include "decomp_types.h"
#include "game/TView.h"
#include "game/CObject.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/quickdraw_guards.h"
#include "game/generated/vcall_facades.h"

// This QuickDraw body keeps the EH-RAII frame but omits the frame pointer.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// TTransFocusAnimation derives from the MFC CObject root: the factory at
// 0x004a0460 installs the shared CObject runtime vtable (0x0066fec4) and the
// class adds no virtuals of its own. CObject supplies the vptr at offset 0; the
// animation fields begin at offset 0x4.
// Duplicate VTABLE annotation removed
class TTransFocusAnimation : public CObject {
public:
  void* scopedRenderTarget; // 0x04
  short field08;            // 0x08
  short field0a;            // 0x0a
  short field0c;            // 0x0c
  char pad_0e[2];
  int field10;      // 0x10
  int field14;      // 0x14
  int field18;      // 0x18
  int sourceLeft;   // 0x1c
  int sourceTop;    // 0x20
  int sourceRight;  // 0x24
  int sourceBottom; // 0x28
  char pad_2c[4];
  int transientSurfaceContext; // 0x30

  void BlitTransientSurfaceToPrimaryRenderContextWithClip();
  void RenderFocusAnimationFrameWithScopedQuickDraw();
};

#include "game/TQuickDrawSurfaceContext.h"
#include "game/quickdraw_globals.h"

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

  reinterpret_cast<void(__cdecl*)(int*)>(thunk_ApplyRectClipRegionToGlobalClipState)(
      &destinationRect.left);
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

  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        reinterpret_cast<TQuickDrawSurfaceContext*>(transientContext)
                            ->GetBlitSurface(),
                        &sourceRect, &destinationRect, 0);
  reinterpret_cast<void(__cdecl*)(int)>(SnapshotHitRegionToClipCache)(surface.surfaceWrapper);
}

// FUNCTION: IMPERIALISM 0x004a0770
void TTransFocusAnimation::RenderFocusAnimationFrameWithScopedQuickDraw() {
  ScopedMapQuickDrawContextGuard quickDrawContext(scopedRenderTarget);
  reinterpret_cast<TView*>(scopedRenderTarget)->Refresh();

  int completionRecord[2];
  completionRecord[0] = 0;
  completionRecord[1] = 0;
  VCall_TransFocusAnimation_CallSlot2C(this, completionRecord);
}
