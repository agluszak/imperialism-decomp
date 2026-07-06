// UI wrapper class quads extracted from trade_screen.

#include "game/TNumberedArrowButton.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>

// SYNTHETIC: IMPERIALISM 0x0058c1e0
// TNumberedArrowButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058c280
// TNumberedArrowButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNumberedArrowButton, TControl)

// FUNCTION: IMPERIALISM 0x0058c2a0
TNumberedArrowButton::TNumberedArrowButton() : TControl(), value84(0), value86(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058c2e0
// TNumberedArrowButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058c330
void TNumberedArrowButton::OrphanCallChain_C1_I08_0058c330(short value84Arg, char refreshFlag) {
  value84 = value84Arg;
  if (refreshFlag != '\0') {
    RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0058c360
void TNumberedArrowButton::OrphanCallChain_C2_I23_0058c360(short value86Arg, char refreshFlag) {
  RECT bounds;
  if (value86 != value86Arg) {
    if (refreshFlag != '\0') {
      RefreshControl();
      QueryBounds(&bounds);
    }
    value86 = value86Arg;
  }
}

// FUNCTION: IMPERIALISM 0x0058c3d0
void TNumberedArrowButton::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);
  RECT srcRect;
  srcRect.left = (value86 != 2) ? 0xa : 0;
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0xb;
  srcRect.bottom = 0x10;
  RECT dstRect = {0, 0, 0xb, 0x10};
  int strategicMapViewSystem = *reinterpret_cast<int*>(kAddrStrategicMapViewSystem);
  TQuickDrawSurfaceContext* hintSource = reinterpret_cast<TQuickDrawSurfaceContext*>(
      *reinterpret_cast<int*>(strategicMapViewSystem + 0x6a4));
  BlitQuickDrawSurfaces(hintSource->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &dstRect,
                        0x24);
  srcRect.left = (value86 != 1) ? 0x21 : 0x16;
  srcRect.right = srcRect.left + 0xb;
  dstRect.top = 0x19;
  dstRect.bottom = 0x29;
  BlitQuickDrawSurfaces(hintSource->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &dstRect,
                        0x24);
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
  reinterpret_cast<void(__cdecl*)(int, int)>(ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor)(0,
                                                                                                10);
  SetQuickDrawTextOriginWithContextOffset(7, 0);
  RefreshControl();
}

// FUNCTION: IMPERIALISM 0x0058c640
void TNumberedArrowButton::DispatchPictureResourceCommand(int eventType, void* eventSender,
                                                          void* eventDataA, void* eventDataB) {
  (void)eventSender;
  (void)eventDataA;
  (void)eventDataB;
  short phase = 0;
  if (eventType >= 0 && eventType < 2) {
    if (value86 != phase) {
      RefreshControl();
      value86 = phase;
    }
    PaintOrInvalidateControl(0);
    return;
  }
  if (eventType == 2 && phase != 0) {
    if (value86 != 0) {
      RefreshControl();
      value86 = 0;
    }
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void TNumberedArrowButton::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* cursorPoint,
                                                                               int hitArg) {
  if (IsActionable() != '\0') {
    if (cursorPoint->y < field38 / 2) {
      field4e = 0x100;
      TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(cursorPoint, hitArg);
      return;
    }
    field4e = (short)0xffff;
  }
  TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(cursorPoint, hitArg);
}
