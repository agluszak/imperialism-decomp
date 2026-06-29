// UI wrapper class quads extracted from trade_screen.

#include "game/TNumberedArrowButton.h"
#include "game/TAmtBar.h"
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

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

void TNumberedArrowButton::OrphanCallChain_C3_I43_0058b750(char mode, char refreshParent) {
  if (mode != *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x64)) {
    *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x64) = mode;
    short bitmapId = 0;
    short modeState = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x98);
    if (mode == 0) {
      if (modeState == 0) {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x90);
      } else if (modeState == 1) {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x94);
      } else {
        bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x96);
      }
    } else {
      bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x92);
    }
    reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
    if (refreshParent != 0) {
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(this)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}

// OrphanCallChain_C2_I37_0058b8d0 — body at 0x0058b8d0 owned by
// THQButton::SetSelectionStateAndRefreshBitmap
void TNumberedArrowButton::OrphanCallChain_C2_I37_0058b8d0(short mode) {
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x98) = mode;
  *reinterpret_cast<char*>(reinterpret_cast<char*>(this) + 0x64) = 0;
  short bitmapId = 0;
  if (mode == 0) {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x90);
  } else if (mode == 1) {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x94);
  } else {
    bitmapId = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x96);
  }
  reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
  reinterpret_cast<TAmtBar*>(this)->SetState(mode != 2, 0);
}

// FUNCTION: IMPERIALISM 0x0058c1e0
TNumberedArrowButton* __cdecl CreateTNumberedArrowButtonInstance(void) {
  return new TNumberedArrowButton();
}
IMPLEMENT_DYNCREATE(TNumberedArrowButton, TControl)

// FUNCTION: IMPERIALISM 0x0058c2a0
TNumberedArrowButton::TNumberedArrowButton() : TControl(), value84(0), value86(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058c2e0
// TNumberedArrowButton::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

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
  reinterpret_cast<void(__cdecl*)(short, short)>(SetQuickDrawTextOriginWithContextOffset)(7, 0);
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
