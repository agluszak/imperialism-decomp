// TCityProductionView temporary QuickDraw render-context slice.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct TCityProductionViewLayout {
  void* vftable;
  char pad_04[0xa2];
  unsigned char needsRefreshAtA6;

  void RenderViewIntoPrimaryRenderContextWithTemporaryClip(int unusedArg1, int unusedArg2);
};

undefined4 ApplyHitRegionToClipState(void);
undefined4 thunk_ApplyRectClipRegionToGlobalClipState(void);
undefined4 thunk_GetActiveQuickDrawSurfaceContextAndFlags(void);
undefined4 thunk_SetActiveQuickDrawSurfaceContext(void);
void __cdecl SnapshotHitRegionToClipCache(int* clipDescriptor);

extern int g_pPrimaryRenderSurfaceContext;

// FUNCTION: IMPERIALISM 0x004bc9b0
void TCityProductionViewLayout::RenderViewIntoPrimaryRenderContextWithTemporaryClip(
    int unusedArg1, int unusedArg2) {
  (void)unusedArg1;
  (void)unusedArg2;

  QuickDrawSurfaceGuard surface;

  int boundsRecord[4];
  VCall_QuickDrawTarget_QueryBoundsSlot12C(this, boundsRecord);

  int clipRect[4];
  clipRect[0] = boundsRecord[0];
  clipRect[1] = boundsRecord[1];
  clipRect[2] = boundsRecord[2];
  clipRect[3] = boundsRecord[3];

  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(0);

  int* previousSurface = 0;
  int contextFlags = 0;
  reinterpret_cast<void(__cdecl*)(int**, int*)>(thunk_GetActiveQuickDrawSurfaceContextAndFlags)(
      &previousSurface, &contextFlags);

  reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
      reinterpret_cast<int*>(g_pPrimaryRenderSurfaceContext), contextFlags);
  reinterpret_cast<void(__cdecl*)(int*)>(thunk_ApplyRectClipRegionToGlobalClipState)(clipRect);

  needsRefreshAtA6 = 1;
  VCall_QuickDrawTarget_ApplyRectSlot110(this, &boundsRecord[1]);

  reinterpret_cast<void(__cdecl*)(int*, int)>(thunk_SetActiveQuickDrawSurfaceContext)(
      previousSurface, contextFlags);
  SnapshotHitRegionToClipCache(0);
}
