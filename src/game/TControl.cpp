// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "game/TControl.h"
#include "game/quickdraw_regions.h"
#include "game/TMouseCaptureState.h"
#include "game/TTEView.h"
#include "game/TMovieView.h"
#include "game/global_data_tables.h"
#include "game/ui_widget_thunks.h"
#include "game/ui_invalidation_guard.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00429450
int TControl::QuerySelectedIndexSlotBC() {
  return hasCommandTagResource;
}

// FUNCTION: IMPERIALISM 0x00429470
void TControl::AssertCityProductionGlobalStateInitialized(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  if (g_McAppUiFlag_006A143C == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
}

// FUNCTION: IMPERIALISM 0x004294a0
char TControl::LogUnhandledDialogMethodAndReturnFalse() {
  TemporarilyClearAndRestoreUiInvalidationFlag();
  return 0;
}

// Slot 0x08 override (0x00435760): TControl cannot be cloned. The original asserts via
// the McAppUI invalidation thunk (file header path, line 0x594) and returns null.

// FUNCTION: IMPERIALISM 0x00435760
TObject* TControl::ShallowClone() {
  TemporarilyClearAndRestoreUiInvalidationFlag();
  return 0;
}
// IMPLEMENT_DYNCREATE also emits `TControl::CreateObject`; the original copy at
// 0x48e430 has the TControl ctor inlined into it.
// SYNTHETIC: IMPERIALISM 0x0048e430
// TControl::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048e500
// TControl::GetRuntimeClass

IMPLEMENT_DYNCREATE(TControl, TView)

TModalTemplateDialogBase::TModalTemplateDialogBase()
    : TView(), hasCommandTagResource(1), commandTagResourceByte(0), field68(0), field6C(0),
      field70(0) {}

// FUNCTION: IMPERIALISM 0x0048e520
TControl::TControl()
    : TModalTemplateDialogBase(), field74(0), textStyle78(g_UiResourceEntryDefaultTextStyle) {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0048e590
// TControl::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0048e640
void TControl::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) {
  (void)arg2;
  (void)arg3;
  (void)arg4;
  int startX = point->x;
  int startY = point->y;
  g_McAppMouseCaptureState.capturedControl = this;
  CWnd::FromHandle(::SetCapture(nativeWindow50->m_hWnd));
  g_McAppMouseCaptureState.startPoint.x = startX;
  g_McAppMouseCaptureState.startPoint.y = startY;
  g_McAppMouseCaptureState.lastPoint.x = startX;
  g_McAppMouseCaptureState.lastPoint.y = startY;
  g_McAppMouseCaptureState.currentPoint.x = startX;
  g_McAppMouseCaptureState.currentPoint.y = startY;
  DispatchPictureResourceCommand(0, &g_McAppMouseCaptureState.startPoint,
                                 &g_McAppMouseCaptureState.lastPoint,
                                 &g_McAppMouseCaptureState.currentPoint, 1);
  if (g_McAppUiMouseCaptureTimerId_006A1ADC == 0) {
    g_McAppUiMouseCaptureTimerId_006A1ADC = SetTimer(
        nativeWindow50->m_hWnd, 0xef, 0x11, NotifyGlobalCaptureOwnerState1WithCachedCoords);
  }
}

// FUNCTION: IMPERIALISM 0x0048e710
void TControl::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
  TEventHandler* child = QueryStepValue();
  if (child != 0) {
    child->DispatchEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7a0
void TControl::SetControlPictureEntryAndMaybeRefresh(int* pictureEntryRef, bool refreshNow) {
  commandTagDefaultParam1 = *pictureEntryRef;
  if (refreshNow) {
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x0048e7d0
void TControl::SetCityProductionDialogPictureRectAndMaybeRefresh(TControlPictureRectState* state,
                                                                 char refreshNow) {
  textStyle78 = *state;
  if (refreshNow != 0) {
    PaintOrInvalidateControl(0);
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
                                              void* eventDataB, int commandFlag) {
  (void)eventSender;
  (void)eventDataA;
  (void)commandFlag;
  if (eventType == 0) {
    SetControlStateFlagAndMaybeRefresh(1, 1);
    return;
  }
  if (eventType == 1) {
    SetControlStateFlagAndMaybeRefresh(
        PointInBoundsAndActionable(reinterpret_cast<CPoint*>(eventDataB)), 1);
    return;
  }
  if (eventType == 2 && PointInBoundsAndActionable(reinterpret_cast<CPoint*>(eventDataB)) != 0) {
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
char TControl::PointInBoundsAndActionable(CPoint* point) {
  RECT rect;
  QueryContentBounds(&rect);
  POINT p;
  p.x = point->x;
  p.y = point->y;
  return PtInRect(&rect, p);
}

// FUNCTION: IMPERIALISM 0x0048e980
void TControl::BuildInsetContentRect(RECT* boundsBuffer) {
  QueryContentBounds(boundsBuffer);
  reinterpret_cast<TTEView*>(boundsBuffer)->DeflateRect(reinterpret_cast<RECT*>(&field68));
}

// FUNCTION: IMPERIALISM 0x0048e9c0
void TControl::NoOpUiViewSlotHandler(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
}

// FUNCTION: IMPERIALISM 0x0048e9e0
undefined TControl::ReturnZeroFromUiSlot6C() {
  return 0;
}

namespace {

HWND ResolvePreModalOwner() {
  if (AfxGetApp() == nullptr || AfxGetApp()->m_pMainWnd == nullptr) {
    return nullptr;
  }
  return AfxGetApp()->m_pMainWnd->GetSafeHwnd();
}

} // namespace

// FUNCTION: IMPERIALISM 0x0049d360
int TModalTemplateDialogBase::PrepareAndCreateModalFromTemplate() {
  void* lockedTemplateBytes = field48;
  field70 = reinterpret_cast<int>(childList44);
  const UINT resourceTemplateId = static_cast<UINT>(resourceTemplateId40);
  if (resourceTemplateId != 0) {
    AFX_MODULE_STATE* moduleState = AfxGetModuleState();
    HMODULE module = moduleState->m_hCurrentInstanceHandle;
    HRSRC resourceInfo = FindResourceA(module, MAKEINTRESOURCEA(resourceTemplateId), RT_DIALOG);
    if (resourceInfo == nullptr) {
      return 0;
    }
    field70 = reinterpret_cast<int>(LoadResource(module, resourceInfo));
  }
  if (reinterpret_cast<HGLOBAL>(field70) != nullptr) {
    lockedTemplateBytes = LockResource(reinterpret_cast<HGLOBAL>(field70));
  }
  if (lockedTemplateBytes == nullptr) {
    return 0;
  }

  field6C = reinterpret_cast<int>(ResolvePreModalOwner());
  field68 = 0;
  if (field6C != 0 && IsWindowEnabled(reinterpret_cast<HWND>(field6C))) {
    EnableWindow(reinterpret_cast<HWND>(field6C), FALSE);
    field68 = 1;
  }
  hasCommandTagResource = reinterpret_cast<int>(::CreateDialogIndirectA(
      AfxGetInstanceHandle(), static_cast<LPCDLGTEMPLATE>(lockedTemplateBytes),
      reinterpret_cast<HWND>(field6C), nullptr));
  field5c = 1;
  return reinterpret_cast<HWND>(hasCommandTagResource) != nullptr ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x0049d450
int TModalTemplateDialogBase::FinalizeModalDialogAndRestoreOwnerFocus() {
  if (field68 != 0) {
    EnableWindow(reinterpret_cast<HWND>(field6C), TRUE);
  }
  if (field6C != 0) {
    HWND activeWindow = GetActiveWindow();
    if (activeWindow == reinterpret_cast<HWND>(hasCommandTagResource)) {
      SetActiveWindow(reinterpret_cast<HWND>(field6C));
    }
  }
  const int result = absoluteX;
  commandTagResourceByte = 1;
  padding_65_to_67[0] = 0;
  padding_65_to_67[1] = 0;
  padding_65_to_67[2] = 0;
  return result;
}

// KNOWN ILT (retired): 0x004087fb is a 5-byte `jmp TControl::TControl` linker stub — not ported.
// Real ctor: TControl::TControl @ 0x0048e520 (base via : TView()).

// FUNCTION: IMPERIALISM 0x0058e440
void TControl::SetHasCommandTagResource(int value) {
  hasCommandTagResource = value;
}

// FUNCTION: IMPERIALISM 0x005bac50
void TControl::RefreshHudNationTitleControlsAndTheme(int themeCode) {
  (void)themeCode;
}

TControl::~TControl() {}

// FUNCTION: IMPERIALISM 0x006050d0
TModalTemplateDialogBase*
TModalTemplateDialogBase::InitializeDialogTemplateFromId(UINT templateId, void* initParam) {
  sharedStringRef.~CString();
  memset(&field3c, 0, 0x20);
  new (&sharedStringRef) CString();
  nativeWindow50 = reinterpret_cast<CWnd*>(initParam);
  field3c = static_cast<int>(templateId);
  resourceTemplateId40 = static_cast<int>(templateId & 0xffff);
  field5c = 0;
  hasCommandTagResource = 0;
  field68 = 0;
  field6C = 0;
  field70 = 0;
  return this;
}
