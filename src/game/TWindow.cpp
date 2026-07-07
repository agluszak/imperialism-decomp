#include "game/TWindow.h"

#include "game/ImperialismApp.h"
#include "game/CMcWindow.h"
#include "game/TApplication.h"
#include "game/TDialogBehavior.h"
#include "game/CWMgrIterator.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

extern CPtrList g_ModalViewStack;

// One-shot McAppUI invalidation-flag assert. The original reaches the shared invalidation
// helper through the incremental-link thunk; each call site is gated by its own
// g_McAppUiFlag_* one-shot so the assert fires at most once.
static __inline void AssertMcAppUiInvalidation(const char* path, int line) {
  (void)path;
  (void)line;
  TemporarilyClearAndRestoreUiInvalidationFlag();
}

// FUNCTION: IMPERIALISM 0x0048d500
TWindow::TWindow() : TView(), dialogBehavior(), field98(0) {
  g_LiveViewRegistry.AddHead(this);
  dialogBehavior.SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);
  field64 = this;
  dialogBehavior.SetDword08(reinterpret_cast<int>(this));
}
// IMPLEMENT_DYNCREATE also emits `TWindow::CreateObject`; the original copy at
// 0x48d090 has the TWindow ctor (including the inlined g_LiveViewRegistry AddHead
// CPlex node code on the 0x6a1a44/0x6a1a50/0x6a1a54/0x6a1a58 globals) inlined into it.
// SYNTHETIC: IMPERIALISM 0x0048d090
// TWindow::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048d220
// TWindow::GetRuntimeClass

IMPLEMENT_DYNCREATE(TWindow, TView)

// SYNTHETIC: IMPERIALISM 0x0048d640
// TWindow::`scalar deleting destructor'
//
// The real (non-deleting) destructor unlinks this window from the global live-view
// registry and from the modal stack; when a window is left on top of the modal stack it
// re-asserts it and re-enables its host window. The TView base destructor then releases
// the child list, the +0x48 buffer and the shared-string member.
// FUNCTION: IMPERIALISM 0x0048d670
TWindow::~TWindow() {
  POSITION pos = g_LiveViewRegistry.Find(this);
  g_LiveViewRegistry.RemoveAt(pos);
  POSITION modalPos = g_ModalViewStack.Find(this);
  if (modalPos != NULL) {
    g_ModalViewStack.RemoveAt(modalPos);
    if (!g_ModalViewStack.IsEmpty()) {
      TWindow* modalTop = static_cast<TWindow*>(g_ModalViewStack.GetHead());
      modalTop->AssertValid();
      if (modalTop->nativeWindow50 != 0) {
        modalTop->nativeWindow50->EnableWindow(1);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048d8a0
void TWindow::SetField88And8c(int param_1, int param_2) {
  dialogBehavior.defaultCommandCode = param_1;
  dialogBehavior.cancelCommandCode = param_2;
}

// FUNCTION: IMPERIALISM 0x0048d8d0
void TWindow::AssertMcAppUILine2358() {
  if (g_McAppUiFlag_006A1B04 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0x936);
  }
}

// FUNCTION: IMPERIALISM 0x0048d900
undefined TWindow::OrphanCallChain_C2_I39_0048d900(char param_1, char param_2) {
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    WPARAM wParam = (param_1 == '\0') ? 3 : 2;
    SendMessageA(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), 0x468, wParam, controlTag);
  }
  if ((int)param_1 != field08) {
    field08 = (int)param_1;
    if (param_2 != '\0') {
      RefreshControl();
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048d980
char TWindow::IsActionable() {
  return field98 != 0 && g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0 && field08 != 0;
}

// FUNCTION: IMPERIALISM 0x0048d9c0
undefined TWindow::SetWindowText(CString* param_1) {
  nativeWindow50->SetWindowText(*param_1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048d9f0
undefined TWindow::GetWindowText(CString* param_1) {
  nativeWindow50->GetWindowText(*param_1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048da10
undefined TWindow::GetDialogBehaviorByte10() {
  TDialogBehavior* behavior = GetEmbeddedDialogBehavior();
  if (behavior != 0) {
    return behavior->field10;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048da40
void TWindow::SetField84(unsigned char param_1) {
  dialogBehavior.field10 = param_1;
}

// Run this window as a modal: optionally arm the dialog-state flag, disable the window
// currently on top of the global modal stack, push self, run the embedded dialog's modal
// loop, then pop self and re-enable the window beneath. Returns the command the dialog
// armed during the loop.
// FUNCTION: IMPERIALISM 0x0048da60
int TWindow::ExecuteViewModalStateWithPushPopChain() {
  TDialogBehavior* behavior = GetEmbeddedDialogBehavior();
  unsigned char wasArmed = behavior->field10;
  if (wasArmed == 0) {
    SetField84(1);
  }
  if (!g_ModalViewStack.IsEmpty()) {
    TWindow* top = static_cast<TWindow*>(g_ModalViewStack.GetHead());
    top->AssertValid();
    if (top->nativeWindow50 != 0) {
      top->nativeWindow50->EnableWindow(0);
    }
  }
  g_ModalViewStack.AddHead(this);
  behavior->CreateTCommandInstance(); // slot 0x12: run the modal message loop
  int armedCommand = behavior->armedCommandCode;
  POSITION pos = g_ModalViewStack.Find(this);
  if (pos != NULL) {
    g_ModalViewStack.RemoveAt(pos);
    if (!g_ModalViewStack.IsEmpty()) {
      TWindow* top = static_cast<TWindow*>(g_ModalViewStack.GetHead());
      top->AssertValid();
      if (top->nativeWindow50 != 0) {
        top->nativeWindow50->EnableWindow(1);
      }
    }
  }
  if (wasArmed == 0) {
    SetField84(0);
  }
  g_pImperialismApp->RestoreWaitCursorIfStartupBusy();
  return armedCommand;
}

// FUNCTION: IMPERIALISM 0x0048dc60
undefined TWindow::GetDialogBehaviorByte20() {
  TDialogBehavior* behavior = GetEmbeddedDialogBehavior();
  if (behavior != 0) {
    return behavior->field20;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0048dc90
undefined TWindow::OrphanCallChain_C2_I12_0048dc90(undefined4 param_1, undefined4 param_2) {
  TDialogBehavior* behavior = GetEmbeddedDialogBehavior();
  if (behavior != 0) {
    behavior->OrphanCallChain_C1_I13_00487430(param_1, param_2);
  }
  return 0;
}

// The 0x74 region is constructed as a real TDialogBehavior (ConstructTDialogBehaviorBaseState
// writes its vptr at +0x74); expose it through its real type so callers dispatch real virtuals.
// FUNCTION: IMPERIALISM 0x0048dcc0
TDialogBehavior* TWindow::GetEmbeddedDialogBehavior() {
  return &dialogBehavior;
}

// FUNCTION: IMPERIALISM 0x0048dce0
void TWindow::AssertMcAppUILine2554() {
  if (g_McAppUiFlag_006A1B08 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0x9fa);
  }
}

// FUNCTION: IMPERIALISM 0x0048dd10
void TWindow::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // Direct access to the embedded TDialogBehavior (the original reads its vptr straight from
  // +0x74), then bubble to HandleEvent.
  dialogBehavior.OrphanCallChain_C1_I17_00487470(commandId, reinterpret_cast<int>(event));
  HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0048dd50
void TWindow::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x1a) {
    if (g_McAppUiFlag_006A1B0C == 0) {
      AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xa1a);
    }
    return;
  }
  TView* child = static_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->DispatchEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048ddc0
undefined TWindow::OrphanCallChain_C2_I19_0048ddc0(TWindow* param_1) {
  if (param_1 == 0) {
    param_1 = this;
  }
  if (param_1 != field64) {
    field64->DispatchUiCommand19ToParent();
    field64 = param_1;
    param_1->HandleCityProductionNoOp();
  }
  return 0;
}

// Realize and show this window: on first call create the host CMcWindow and propagate the
// UI resource context into every child control, then notify the window, run the
// not-actionable fallback (mark busy, poke the linked window, fire the slot-0x73 chain),
// and finally recurse the realize hook into each child.
// FUNCTION: IMPERIALISM 0x0048de00
void TWindow::DispatchSlot9CToLinkedChildren() {
  if (nativeWindow50 == 0) {
    nativeWindow50 = new CMcWindow(this);
    if (childList44 != 0) {
      POSITION pos = childList44->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList44->GetNext(pos));
        child->PropagateUiResourceContextRecursive(nativeWindow50);
      }
    }
  }
  ::SendMessageA(nativeWindow50->m_hWnd, 0x468, 0, controlTag);
  if (IsActionable() == 0) {
    field98 = 1;
    if (field64 != 0) {
      field64->vmethod_0081(0);
    }
    OrphanCallChain_C2_I39_0048d900(1, 1);
  }
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->DispatchSlot9CToLinkedChildren();
    }
  }
}

// Clear the busy flag, notify the host window, recurse the slot-0x28 hook into every child
// control, then run the slot-0x73 state-notify chain.
// FUNCTION: IMPERIALISM 0x0048e060
void TWindow::CallVoidSlotA0() {
  field98 = 0;
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    SendMessageA(reinterpret_cast<HWND>(nativeWindow50->m_hWnd), 0x468, 1, controlTag);
  }
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->CallVoidSlotA0();
    }
  }
  OrphanCallChain_C2_I39_0048d900(0, 1);
}

// FUNCTION: IMPERIALISM 0x0048e120
void TWindow::CloseAndFree() {
  CallVoidSlotA0();
  Free();
}

// FUNCTION: IMPERIALISM 0x0048e150
undefined TWindow::WrapperFor_CenterWindowWithinOwnerOrWorkArea_At0048e150(char param_1,
                                                                           char param_2) {
  if (nativeWindow50 != 0) {
    nativeWindow50->CenterWindow(0);
    return 0;
  }
  if (param_1 != 0) {
    ownerLocalX = (0x280 - field34) / 2;
  }
  if (param_2 != 0) {
    ownerLocalY = (0x1e0 - field38) / 2;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048e1c0
char TWindow::TestPointInBounds(CPoint* point) {
  return 3;
}

// FUNCTION: IMPERIALISM 0x0048e1e0
void TWindow::ReturnFromUiSlot60(int arg) {
  (void)arg;
  if (g_McAppUiFlag_006A1B10 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xac4);
  }
}

// FUNCTION: IMPERIALISM 0x0048e210
void TWindow::ReturnFromUiSlot61(int arg) {
  (void)arg;
  if (g_McAppUiFlag_006A1B14 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xad9);
  }
}

// FUNCTION: IMPERIALISM 0x0048e240
void TWindow::ReturnFromUiSlot62(int arg) {
  (void)arg;
  if (g_McAppUiFlag_006A1B18 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xaee);
  }
}

// FUNCTION: IMPERIALISM 0x0048e270
void TWindow::ReturnFromUiSlot63(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;
  if (g_McAppUiFlag_006A1B1C == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xaff);
  }
}

// Object teardown: destroy/notify the host CMcWindow, free all child controls, detach from
// the owner, hand off the active-view slot, release the linked resource-owner target, then delete
// self. Uses the real MFC CWnd/CObject surface (IsKindOf/AssertValid/dtor) directly.
// FUNCTION: IMPERIALISM 0x0048e2a0
void TWindow::Free() {
  CWnd* window = nativeWindow50;
  if (window != 0) {
    if (window->m_hWnd != 0) {
      ::SendMessageA(window->m_hWnd, 0x4ef, 0, controlTag);
      ::SendMessageA(nativeWindow50->m_hWnd, 0x468, 4, controlTag);
    } else {
      if (window->IsKindOf(RUNTIME_CLASS(CMcWindow))) {
        CMcWindow* mcWindow = static_cast<CMcWindow*>(nativeWindow50);
        mcWindow->AssertValid();
        mcWindow->m_pOwnerWindow = 0;
        delete mcWindow;
      } else {
        delete nativeWindow50;
      }
      nativeWindow50 = 0;
    }
  }
  while (childList44 != 0) {
    static_cast<TView*>(childList44->GetHead())->Free();
  }
  if (ownerContext != 0) {
    ownerContext->DetachChildFromOwnerList(this);
    ownerContext = 0;
  }
  if (g_pApplicationUiRootController != 0 &&
      g_pApplicationUiRootController != reinterpret_cast<TApplication*>(this)) {
    if (g_pApplicationUiRootController->GetActiveView() == reinterpret_cast<TView*>(this)) {
      TView* replacement = static_cast<TView*>(QueryStepValue());
      if (replacement == 0) {
        g_pApplicationUiRootController->SetActiveView(
            reinterpret_cast<TView*>(g_pApplicationUiRootController));
      } else {
        g_pApplicationUiRootController->SetActiveView(replacement);
      }
    }
  }
  field0c = 0;
  if (linkedResourceOwner != 0) {
    linkedResourceOwner->Free();
  }
  linkedResourceOwner = 0;
  delete this;
}

// FUNCTION: IMPERIALISM 0x00492cc0
class TView* TWindow::OwnerPanel() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00492ce0
class TView* TWindow::QueryOwnerContextPanel() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00492d00
void TWindow::TranslatePointToParentChain4E(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d20
void TWindow::TranslatePointToParentChain4D(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d40
void TWindow::DispatchVslot134WithRectAndRectPlus8_Impl(RECT* rect) {}

// FUNCTION: IMPERIALISM 0x00492d60
void TWindow::SubtractPosAndDispatchToOwnerSlot19C(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d80
TObject* TWindow::ShallowClone() {
  AssertMcAppUiInvalidation(g_szMcAppUiHeaderPath_006943CC, 0x51e);
  return 0;
}
