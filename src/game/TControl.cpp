// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

#include "game/TControl.h"
#include "game/ClipStateRegion.h"
#include "game/TTEView.h"
#include "game/mcappui_globals.h"
#include "game/ui_widget_thunks.h"

#include <new>

extern "C" {
extern int g_nUiResourceEntryDefaultParam0;
extern int g_nUiResourceEntryDefaultParam1;
extern unsigned short g_wUiResourceEntryDefaultParam2;
extern CRuntimeClass PTR_s_TControl_00649600;
}

undefined4 FromHandle(void);
undefined4 GetRegionBoxToRectIfPresent(void);
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);
extern "C" char LAB_00409a9d;
// FUNCTION: IMPERIALISM 0x004087fb
void __fastcall ConstructTControlBaseStateThunk(TControl* self) {
  new (self) TControl();
}

// FUNCTION: IMPERIALISM 0x00429450
int TControl::QuerySelectedIndexSlotBC() {
  return hasCommandTagResource;
}

// FUNCTION: IMPERIALISM 0x00429470
void TControl::AssertCityProductionGlobalStateInitialized(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  if (g_McAppUiFlag_006A143C == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(g_szMcAppUiHeaderPath_006943CC, 0x56f);
  }
}

// FUNCTION: IMPERIALISM 0x004294a0
char TControl::LogUnhandledDialogMethodAndReturnFalse() {
  reinterpret_cast<void(__cdecl*)(const char*, int)>(
      thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(g_szMcAppUiHeaderPath_006943CC, 0x58f);
  return 0;
}

// Slot 0x08 override (0x00435760): TControl cannot be cloned. The original asserts via
// the McAppUI invalidation thunk (file header path, line 0x594) and returns null.
// FUNCTION: IMPERIALISM 0x00435760
void* TControl::CloneEngineerDialogStateToNewInstance() {
  reinterpret_cast<void(__cdecl*)(const char*, int)>(
      thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(g_szMcAppUiHeaderPath_006943CC, 0x594);
  return 0;
}






// FUNCTION: IMPERIALISM 0x0048e500
CRuntimeClass* TControl::GetRuntimeClass() {
  return &PTR_s_TControl_00649600;
}

// Real ctor: the TView base ctor runs first (constructs the TView subobject +
// its CString member), then MSVC writes this class's vptr (0x0064a098). Fields
// are member-initializers so they emit in declaration order. No manual vtable
// writes — the // VTABLE: annotation owns 0x0064a098.
// FUNCTION: IMPERIALISM 0x0048e520
TControl::TControl()
    : hasCommandTagResource(1), commandTagResourceByte(0), contentMargins68(),
      commandTagDefaultParam0(g_nUiResourceEntryDefaultParam0),
      commandTagDefaultParam1(g_nUiResourceEntryDefaultParam1),
      commandTagDefaultParam2(g_wUiResourceEntryDefaultParam2) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0048e590
// TControl::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0048e640
void TControl::BeginMouseCaptureAndStartRepeatTimer(Point32* point) {
  g_McAppUiMouseCaptureControl_006A1A80 = this;
  void* capturedWindow = reinterpret_cast<void*>(SetCapture(reinterpret_cast<HWND>(nativeWindow50->hwnd)));
  reinterpret_cast<void(__cdecl*)(void*)>(FromHandle)(capturedWindow);
  g_McAppUiMouseCaptureStartPoint_006A1A68[0] = point->x;
  g_McAppUiMouseCaptureStartPoint_006A1A68[1] = point->y;
  g_McAppUiMouseCaptureLastPoint_006A1A70[0] = point->x;
  g_McAppUiMouseCaptureLastPoint_006A1A70[1] = point->y;
  g_McAppUiMouseCaptureCurrentPoint_006A1A78[0] = point->x;
  g_McAppUiMouseCaptureCurrentPoint_006A1A78[1] = point->y;
  DispatchPictureResourceCommand(0, g_McAppUiMouseCaptureStartPoint_006A1A68,
                                 g_McAppUiMouseCaptureLastPoint_006A1A70,
                                 g_McAppUiMouseCaptureCurrentPoint_006A1A78);
  if (g_McAppUiMouseCaptureTimerId_006A1ADC == 0) {
    g_McAppUiMouseCaptureTimerId_006A1ADC =
        SetTimer(reinterpret_cast<HWND>(nativeWindow50->hwnd), 0xef, 0x11, reinterpret_cast<TIMERPROC>(&LAB_00409a9d));
  }
}

// FUNCTION: IMPERIALISM 0x0048e710
void TControl::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)sourceHandler;
  (void)event;
  if (commandId == 0x1f) {
    SetControlStateFlagAndMaybeRefresh(1, 1);
    return;
  }
  if (commandId == 0x20) {
    SetControlStateFlagAndMaybeRefresh(0, 1);
    return;
  }
  if (commandId == 0x21) {
    SetControlStateFlagAndMaybeRefresh(commandTagResourceByte == 0, 1);
    return;
  }
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->DispatchEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7a0
void TControl::SetControlPictureEntryAndMaybeRefresh(int* pictureEntryRef, bool refreshNow) {
  commandTagDefaultParam1 = *pictureEntryRef;
  if (refreshNow) {
    vmethod_0048(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7d0
void TControl::SetCityProductionDialogPictureRectAndMaybeRefresh(TControlPictureRectState* state,
                                                                 char refreshNow) {
  commandTagDefaultParam0 = state->value0;
  commandTagDefaultParam1 = state->value1;
  commandTagDefaultParam2 = state->value2;
  if (refreshNow != 0) {
    vmethod_0048(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e810
void TControl::SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) {
  if (commandTagResourceByte != static_cast<unsigned char>(enabledState)) {
    commandTagResourceByte = static_cast<unsigned char>(enabledState);
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048e850
void TControl::DispatchPictureResourceCommand(int eventType, void* eventSender, void* eventDataA,
                                              void* eventDataB) {
  (void)eventSender;
  if (eventType == 0) {
    SetControlStateFlagAndMaybeRefresh(1, 1);
    return;
  }
  if (eventType == 1) {
    SetControlStateFlagAndMaybeRefresh(
        PointInBoundsAndActionable(reinterpret_cast<Point32*>(eventDataB)), 1);
    return;
  }
  if (eventType == 2 && PointInBoundsAndActionable(reinterpret_cast<Point32*>(eventDataB)) != 0) {
    if (hasCommandTagResource == 4) {
      DispatchEvent(0x21, this, 0);
      DispatchEvent(hasCommandTagResource, this, 0);
      return;
    }
    if (hasCommandTagResource != 0xc) {
      DispatchEvent(0x20, this, 0);
      DispatchEvent(hasCommandTagResource, this, 0);
      return;
    }
    DispatchEvent(0x1f, this, 0);
    DispatchEvent(hasCommandTagResource, this, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e940
char TControl::PointInBoundsAndActionable(Point32* point) {
  RECT rect;
  QueryContentBounds(&rect);
  POINT p;
  p.x = point->x;
  p.y = point->y;
  return PtInRect(&rect, p);
}

// FUNCTION: IMPERIALISM 0x0048e980
void TControl::SwitchTab(int* boundsBuffer) {
  QueryContentBounds(reinterpret_cast<RECT*>(boundsBuffer));
  reinterpret_cast<TTEView*>(boundsBuffer)->DeflateRect(&contentMargins68);
}

void TControl::WrapperFor_ApplyRectMarginsInPlace_At0048e980(int* boundsBuffer) {
  SwitchTab(boundsBuffer);
}

// FUNCTION: IMPERIALISM 0x0048e9c0
void TControl::NoOpCityProductionDialogMethod(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x0048e9e0
void TControl::NoOpCityProductionDialogPictureHook(int arg) {
  (void)arg;
}

// KNOWN LINKER ARTIFACT: 0x004087fb is `jmp TControl::TControl`.

// FUNCTION: IMPERIALISM 0x0058e440
void TControl::OrphanTiny_SetDwordEcxOffset_60_0058e440(int value) {
  hasCommandTagResource = value;
}
