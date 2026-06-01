// Shared wrapped-map QuickDraw overlay helpers.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"
#include "game/ui_widget_shared.h"

// This wrapped-map overlay body is EH guarded but still frame-pointer omitted
// in the original, unlike the larger amount-bar DrawAmt bodies.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" short __stdcall GetAsyncKeyState(int virtual_key_code);

undefined4 thunk_NormalizeWrappedMapCoord108x60(void);
undefined4 ComputeStridedRecordAddress6C(void);

// GLOBAL: IMPERIALISM 0x006a1344
int g_pGlobalUiRootController = 0;

// FUNCTION: IMPERIALISM 0x00596100
void __fastcall RenderWrappedMapQuickDrawOverlayFromStridedRecords(void* overlayView,
                                                                   int unusedEdx,
                                                                   int overlayRecord) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  QuickDrawSurfaceGuard surface;

  short tileX = 0;
  short tileY = 0;
  int dispatchContext = 0;
  VCall_MapOverlay_QueryWrappedTileSlot1C0(overlayView, overlayRecord, &tileX, &tileY,
                                           &dispatchContext);
  reinterpret_cast<void(__cdecl*)(short*, short*)>(thunk_NormalizeWrappedMapCoord108x60)(&tileX,
                                                                                         &tileY);

  int stridedRecord =
      reinterpret_cast<int(__cdecl*)(int, int)>(ComputeStridedRecordAddress6C)((int)tileX,
                                                                               (int)tileY);
  if (*reinterpret_cast<int*>(overlayRecord + 0x24) == 1) {
    VCall_MapOverlay_DrawForcedSlot1CC(overlayView, stridedRecord, dispatchContext);
    return;
  }

  if (((unsigned short)GetAsyncKeyState(0x11) & 0x8000) != 0) {
    VCall_MapOverlay_DrawCtrlModifiedSlot1C4(overlayView, stridedRecord, dispatchContext);
    return;
  }

  if (((unsigned short)GetAsyncKeyState(0x10) & 0x8000) != 0) {
    VCall_MapOverlay_DrawForcedSlot1CC(overlayView, stridedRecord, dispatchContext);
    return;
  }

  if (*reinterpret_cast<int*>(g_pGlobalUiRootController + 0x24) < 2) {
    VCall_MapOverlay_DrawRootModeLowSlot1D4(overlayView, stridedRecord, dispatchContext);
    return;
  }

  VCall_MapOverlay_DrawRootModeHighSlot1D0(overlayView, stridedRecord, dispatchContext);
}
