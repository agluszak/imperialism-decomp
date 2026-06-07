// TTransFocusAnimation vertical-slice implementations.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

// This QuickDraw body keeps the EH-RAII frame but omits the frame pointer.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TTransFocusAnimationLayout {
  void* vftable;
  void* scopedRenderTarget;
  short field08;
  short field0a;
  short field0c;
  char pad_0e[2];
  int field10;
  int field14;
  int field18;
  int sourceLeft;
  int sourceTop;
  int sourceRight;
  int sourceBottom;
  char pad_2c[4];
  int transientSurfaceContext;
};

undefined4 ApplyHitRegionToClipState(void);
undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
undefined4 ResetQuickDrawStrokeState(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);
undefined4 BlitRectWithOptionalTransparency(void);
void __cdecl SnapshotHitRegionToClipCache(int* clipDescriptor);

// GLOBAL: IMPERIALISM 0x006a30a8
int g_pPrimaryRenderSurfaceContext = 0;

// FUNCTION: IMPERIALISM 0x004a05c0
void __fastcall
BlitTransientSurfaceToPrimaryRenderContextWithClip(TTransFocusAnimationLayout* focusAnimation,
                                                   int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  QuickDrawSurfaceGuard surface;
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  RECT destinationRect;
  RECT sourceRect;
  destinationRect.left = 0;
  destinationRect.top = 0;
  sourceRect.left = focusAnimation->sourceLeft;
  sourceRect.top = focusAnimation->sourceTop;
  sourceRect.right = focusAnimation->sourceRight;
  destinationRect.right = sourceRect.right - sourceRect.left;
  sourceRect.bottom = focusAnimation->sourceBottom;
  destinationRect.bottom = sourceRect.bottom - sourceRect.top;

  reinterpret_cast<void(__cdecl*)(int*)>(thunk_ApplyRectClipRegionToGlobalClipState)(
      &destinationRect.left);
  reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(0);

  int(__stdcall * offsetRect)(RECT*, int, int) = OffsetRect;
  int primaryFlipDescriptor = *reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext + 0x20);
  if (primaryFlipDescriptor != 0) {
    int primaryFlipHeight =
        *reinterpret_cast<int*>(*reinterpret_cast<int*>(primaryFlipDescriptor + 0x10) + 8);
    if (primaryFlipHeight < 1) {
      primaryFlipHeight = -primaryFlipHeight;
    }
    offsetRect(&sourceRect, 0, (primaryFlipHeight - sourceRect.top) - sourceRect.bottom);
  }

  int transientContext = focusAnimation->transientSurfaceContext;
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

  reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, int, void*)>(
      BlitRectWithOptionalTransparency)(reinterpret_cast<void*>(g_pPrimaryRenderSurfaceContext + 4),
                                        reinterpret_cast<void*>(transientContext + 4), &sourceRect,
                                        &destinationRect, 0, 0);
  reinterpret_cast<void(__cdecl*)(int)>(SnapshotHitRegionToClipCache)(surface.surfaceWrapper);
}

// FUNCTION: IMPERIALISM 0x004a0770
void __fastcall
RenderFocusAnimationFrameWithScopedQuickDraw(TTransFocusAnimationLayout* focusAnimation,
                                             int unusedEdx) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  ScopedMapQuickDrawContextGuard quickDrawContext(focusAnimation->scopedRenderTarget);
  VCall_FocusAnimationView_RenderSlotF8(focusAnimation->scopedRenderTarget);

  int completionRecord[2];
  completionRecord[0] = 0;
  completionRecord[1] = 0;
  VCall_TransFocusAnimation_CallSlot2C(focusAnimation, completionRecord);
}
