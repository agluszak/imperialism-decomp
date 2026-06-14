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

// FUNCTION: IMPERIALISM 0x0048e980
void TControl::SwitchTab(int* boundsBuffer) {
  QueryContentBounds(reinterpret_cast<RECT*>(boundsBuffer));
  reinterpret_cast<TTEView*>(boundsBuffer)->DeflateRect(&contentMargins68);
}

void TControl::WrapperFor_ApplyRectMarginsInPlace_At0048e980(int* boundsBuffer) {
  SwitchTab(boundsBuffer);
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

// FUNCTION: IMPERIALISM 0x0048e9c0
void TControl::NoOpCityProductionDialogMethod(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x0048e9e0
void TControl::NoOpCityProductionDialogPictureHook(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004294a0
char TControl::LogUnhandledDialogMethodAndReturnFalse() {
  reinterpret_cast<void(__cdecl*)(const char*, int)>(
      thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(g_szMcAppUiHeaderPath_006943CC, 0x58f);
  return 0;
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

// FUNCTION: IMPERIALISM 0x0048c080
void TControl::HandleCursorHoverSelectionByChildHitTestAndFallback(Point32* point, int hitArg) {
  if (HasRenderableParentAndContent() != 0) {
    CPtrListNode* node = childList44 != 0 ? childList44->headNode : 0;
    while (node != 0) {
      TView* child = reinterpret_cast<TView*>(node->data);
      node = node->next;

      Point32 childPoint = *point;
      child->UpdateAfterBitmapChange(reinterpret_cast<int>(&childPoint));
      if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
          child->EvaluateControlInputGate() != 0) {
        child->HandleCursorHoverSelectionByChildHitTestAndFallback(&childPoint, hitArg);
        return;
      }
    }
  }

  if (reinterpret_cast<char(__cdecl*)(int)>(GetRegionBoxToRectIfPresent)(hitArg) != 0 &&
      Refresh() != 0) {
    HandleCursorHoverFallback(point, hitArg);
  }
}

// FUNCTION: IMPERIALISM 0x0048c450
char TControl::DispatchUiMouseMoveToChildren(Point32* point, int arg2, int arg3, int arg4) {
  CPtrListNode* node = childList44 != 0 ? childList44->headNode : 0;
  while (node != 0) {
    TView* child = reinterpret_cast<TView*>(node->data);
    node = node->next;

    Point32 childPoint = *point;
    child->UpdateAfterBitmapChange(reinterpret_cast<int>(&childPoint));
    if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
        child->DispatchUiMouseMoveToChildren(&childPoint, arg2, arg3, arg4) != 0) {
      return 1;
    }
  }

  if (Refresh() != 0 && GetBoolSlot28() != 0) {
    Point32 localPoint = *point;
    BeginMouseCaptureAndStartRepeatTimer(&localPoint);
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048c590
char TControl::DispatchUiMouseEventToChildrenOrSelf_Impl(Point32* point, int arg2, int arg3,
                                                         int arg4) {
  CPtrListNode* node = childList44 != 0 ? childList44->headNode : 0;
  while (node != 0) {
    TView* child = reinterpret_cast<TView*>(node->data);
    node = node->next;

    Point32 childPoint = *point;
    child->UpdateAfterBitmapChange(reinterpret_cast<int>(&childPoint));
    if (child->PointInBoundsAndActionable(&childPoint) != 0 &&
        child->DispatchUiMouseEventToChildrenOrSelf_Impl(&childPoint, arg2, arg3, arg4) != 0) {
      return 1;
    }
  }

  if (Refresh() != 0) {
    Point32 localPoint = *point;
    if (GetBoolSlot28() != 0) {
      return vmethod_0071(&localPoint, arg2, arg3, arg4) != 0;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048b8d0
void TControl::PaintVisibleChildrenIntersectingClipRect(RECT* clipRect, int bindArg) {
  if (g_McAppUiActiveFlag_006950AC == 0 || IsActionable() == 0 || Refresh() == 0) {
    return;
  }

  RECT clippedRect;
  QueryContentBounds(&clippedRect);
  if (IntersectRect(&clippedRect, &clippedRect, clipRect) == 0) {
    return;
  }

  if (BindMapQuickDrawDc(bindArg) != 0) {
    ApplyRectSlot110(&clippedRect);
    if (field18 != 0) {
      reinterpret_cast<TEventHandler*>(field18)->vmethod_0013(reinterpret_cast<int*>(&clippedRect));
    }
    ReleaseMapQuickDrawDc(bindArg);
  }

  CPtrListNode* node = childList44 != 0 ? childList44->headNode : 0;
  while (node != 0) {
    CPtrListNode* next = node->next;
    TView* child = reinterpret_cast<TView*>(node->data);
    RECT childClip = clippedRect;
    OffsetRect(&childClip, -child->ownerOffsetX, -child->ownerOffsetY);
    RECT childPaintRect;
    CopyRect(&childPaintRect, &childClip);
    child->PaintVisibleChildrenIntersectingClipRect(&childPaintRect, bindArg);
    node = next;
  }
}

// FUNCTION: IMPERIALISM 0x0048b4b0
void TControl::InvalidateOffsetRegionUsingChildClipRect(int* regionWrapper) {
  if (nativeWindow50 == 0) {
    return;
  }

  int* localRegion = reinterpret_cast<int*>(
      reinterpret_cast<int(__cdecl*)()>(CreateClipStateRegionWrapperObject)());
  if (localRegion == 0 || *localRegion == 0) {
    return;
  }

  void* sourceRegion = 0;
  if (regionWrapper != 0 && *regionWrapper != -0x14) {
    sourceRegion = *reinterpret_cast<void**>(*regionWrapper + 0x18);
  }
  void* destRegion = *reinterpret_cast<void**>(*localRegion + 0x18);
  CombineRgn(reinterpret_cast<HRGN>(destRegion), reinterpret_cast<HRGN>(sourceRegion), nullptr, 5);

  Point32 cachedPos;
  Point32* pos = reinterpret_cast<Point32*>(GetCachedPosPoint(reinterpret_cast<int*>(&cachedPos)));
  OffsetRgn(reinterpret_cast<HRGN>(destRegion), -pos->x, -pos->y);

  if (g_McAppUiActiveFlag_006950AC != 0) {
    InvalidateRgn(reinterpret_cast<HWND>(nativeWindow50->hwnd), reinterpret_cast<HRGN>(destRegion), 0);
  }

  reinterpret_cast<void(__cdecl*)(int*)>(DestroyClipStateRegionWrapperObject)(localRegion);
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

// FUNCTION: IMPERIALISM 0x0058e440
void TControl::OrphanTiny_SetDwordEcxOffset_60_0058e440(int value) {
  hasCommandTagResource = value;
}

// FUNCTION: IMPERIALISM 0x0058c7c0
void TControl::WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
    int* cursorPoint, int hitArg) {
  if (IsActionable() != '\0') {
    if (cursorPoint[1] < field38 / 2) {
      field4e = 0x100;
      reinterpret_cast<void(__fastcall*)(TControl*, int, int*, int)>(
          thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(this, 0, cursorPoint, hitArg);
      return;
    }
    field4e = (short)0xffff;
  }
  reinterpret_cast<void(__fastcall*)(TControl*, int, int*, int)>(
      thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(this, 0, cursorPoint, hitArg);
}

// KNOWN LINKER ARTIFACT: 0x004087fb is `jmp TControl::TControl`.
// FUNCTION: IMPERIALISM 0x004087fb
void __fastcall ConstructTControlBaseStateThunk(TControl* self) {
  new (self) TControl();
}
