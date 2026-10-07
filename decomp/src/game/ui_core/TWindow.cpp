#include "game/ui_core/TWindow.h"
#include "game/globals/view_registries.h"
#include "game/ui_tags_common.h"

#include "game/ImperialismApp.h"
#include "game/ui_core/CMcWindow.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/CWMgrIterator.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeObservation.h"
#include "RuntimeTestDriver.h"
#endif

// IMPLEMENT_DYNCREATE also emits `TWindow::CreateObject`; the original copy at
// 0x48d090 has the TWindow ctor (including the inlined g_LiveViewRegistry AddHead
// CPlex node code on the 0x6a1a44/0x6a1a50/0x6a1a54/0x6a1a58 globals) inlined into it.

IMPLEMENT_DYNCREATE(TWindow, TView)

// FUNCTION: IMPERIALISM 0x0048d670
TWindow::~TWindow() {
  POSITION pos = g_LiveViewRegistry.Find(this);
  g_LiveViewRegistry.RemoveAt(pos);
  POSITION modalPos = g_ModalViewStack.Find(this);
  if (modalPos != NULL) {
    g_ModalViewStack.RemoveAt(modalPos);
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTestDriver::ObserveDeferred(kObserveModalPopped);
#endif
    if (!g_ModalViewStack.IsEmpty()) {
      TWindow* modalTop = g_ModalViewStack.GetHead();
      modalTop->AssertValid();
      if (modalTop->nativeWindow != 0) {
        modalTop->nativeWindow->EnableWindow(1);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048d870
void __stdcall AssertMcAppUiDialogStateAndReturn(int arg1, int arg2, int arg3, int arg4, int arg5) {
  ReportAssertionFailure(g_szMcAppUiSourcePath, 0x8c9);
}

// FUNCTION: IMPERIALISM 0x0048d8a0
void TWindow::SetDialogItems(unsigned long defaultCommandCode, unsigned long cancelCommandCode) {
  dialogBehavior.defaultCommandCode = defaultCommandCode;
  dialogBehavior.cancelCommandCode = cancelCommandCode;
}

// FUNCTION: IMPERIALISM 0x0048d8d0
void TWindow::Activate(unsigned char) {
  if (g_McAppUiFlag_006A1B04 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x936);
  }
}

// FUNCTION: IMPERIALISM 0x0048d900
void TWindow::Show(unsigned char show, bool refresh) {
  if (nativeWindow != 0 && nativeWindow->m_hWnd != 0) {
    WPARAM wParam = show == 0 ? 3 : 2;
    SendMessageA(nativeWindow->m_hWnd, 0x468, wParam, controlTag);
  }
  if ((int)show != viewEnabled) {
    viewEnabled = (int)show;
    if (refresh) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048d980
bool TWindow::IsActionable() {
  return busyFlag != 0 && g_McAppUiActiveFlag != 0 && nativeWindow != 0 && viewEnabled != 0;
}

// FUNCTION: IMPERIALISM 0x0048d9c0
void TWindow::SetTitle(const CString* title) {
  nativeWindow->SetWindowText(*title);
}

// FUNCTION: IMPERIALISM 0x0048d9f0
void TWindow::GetTitle(CString* title) {
  nativeWindow->GetWindowText(*title);
}

// FUNCTION: IMPERIALISM 0x0048da10
bool TWindow::IsModal() {
  TDialogBehavior* behavior = GetDialogBehavior();
  if (behavior != 0) {
    return behavior->armed;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x0048da40
void TWindow::SetModality(bool modal) {
  dialogBehavior.armed = modal;
}

// FUNCTION: IMPERIALISM 0x0048da60
int TWindow::PoseModally() {
  TDialogBehavior* behavior = GetDialogBehavior();
  bool wasArmed = behavior->armed;
  if (!wasArmed) {
    SetModality(true);
  }
  if (!g_ModalViewStack.IsEmpty()) {
    TWindow* top = g_ModalViewStack.GetHead();
    top->AssertValid();
    if (top->nativeWindow != 0) {
      top->nativeWindow->EnableWindow(0);
    }
  }
  g_ModalViewStack.AddHead(this);
  behavior->PoseModally(); // slot 0x12: run the modal message loop
  int armedCommand = behavior->armedCommandCode;
  POSITION pos = g_ModalViewStack.Find(this);
  if (pos != NULL) {
    g_ModalViewStack.RemoveAt(pos);
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTestDriver::ObserveDeferred(kObserveModalPopped);
#endif
    if (!g_ModalViewStack.IsEmpty()) {
      TWindow* top = g_ModalViewStack.GetHead();
      top->AssertValid();
      if (top->nativeWindow != 0) {
        top->nativeWindow->EnableWindow(1);
      }
    }
  }
  if (!wasArmed) {
    SetModality(false);
  }
  g_pImperialismApp->RestoreWaitCursorIfStartupBusy();
  return armedCommand;
}

// FUNCTION: IMPERIALISM 0x0048dc60
bool TWindow::IsDismissed() {
  TDialogBehavior* behavior = GetDialogBehavior();
  if (behavior != 0) {
    return behavior->dismissPending;
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x0048dc90
void TWindow::Dismiss(unsigned long commandCode, bool accepted) {
  TDialogBehavior* behavior = GetDialogBehavior();
  if (behavior != 0) {
    behavior->Dismiss(commandCode, accepted);
  }
}

// FUNCTION: IMPERIALISM 0x0048dcc0
TDialogBehavior* TWindow::GetDialogBehavior() {
  return &dialogBehavior;
}

// FUNCTION: IMPERIALISM 0x0048dce0
void TWindow::AssertMcAppUILine2554() {
  if (g_McAppUiFlag_006A1B08 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x9fa);
  }
}

// FUNCTION: IMPERIALISM 0x0048dd10
void TWindow::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  dialogBehavior.DoEvent(commandId, sourceHandler, event);
  DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0048dd50
void TWindow::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x1a) {
    if (g_McAppUiFlag_006A1B0C == 0) {
      ReportAssertionFailure(g_szMcAppUiSourcePath, 0xa1a);
    }
    return;
  }
  TView* child = static_cast<TView*>(GetNextHandler());
  if (child != 0) {
    child->HandleEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048ddc0
void TWindow::SetWindowTarget(TEventHandler* target) {
  if (target == 0) {
    target = this;
  }
  if (target != activeLinkedWindow) {
    activeLinkedWindow->BecameWindowTarget();
    activeLinkedWindow = target;
    target->TargetValidationSucceeded();
  }
}

// FUNCTION: IMPERIALISM 0x0048de00
CWnd* TWindow::Open() {
  if (nativeWindow == 0) {
    nativeWindow = new CMcWindow(this);
    if (childList != 0) {
      POSITION pos = childList->GetHeadPosition();
      while (pos != NULL) {
        TView* child = static_cast<TView*>(childList->GetNext(pos));
        child->PropagateUiResourceContextRecursive(nativeWindow);
      }
    }
  }
  ::SendMessageA(nativeWindow->m_hWnd, 0x468, 0, controlTag);
  if (!IsActionable()) {
    busyFlag = 1;
    if (activeLinkedWindow != 0) {
      activeLinkedWindow->SelectOwner(0);
    }
    Show(1, true);
  }
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->Open();
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048e060
void TWindow::Close() {
  busyFlag = 0;
  if (nativeWindow != 0 && nativeWindow->m_hWnd != 0) {
    SendMessageA(nativeWindow->m_hWnd, 0x468, 1, controlTag);
  }
  if (childList != 0) {
    POSITION pos = childList->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList->GetNext(pos));
      child->Close();
    }
  }
  Show(0, true);
}

// FUNCTION: IMPERIALISM 0x0048e120
void TWindow::CloseAndFree() {
  Close();
  Free();
}

// FUNCTION: IMPERIALISM 0x0048e150
void TWindow::Center(bool centerX, bool centerY, bool unused) {
  if (nativeWindow != 0) {
    nativeWindow->CenterWindow(0);
    return;
  }
  if (centerX) {
    ownerLocalX = (0x280 - frameWidth) / 2;
  }
  if (centerY) {
    ownerLocalY = (0x1e0 - frameHeight) / 2;
  }
}

// FUNCTION: IMPERIALISM 0x0048e1c0
short TWindow::ContainsMouse(const CPoint& point) {
  return 3;
}

// FUNCTION: IMPERIALISM 0x0048e1e0
void TWindow::GoAwayByUser(const CPoint& point) {
  if (g_McAppUiFlag_006A1B10 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0xac4);
  }
}

// FUNCTION: IMPERIALISM 0x0048e210
void TWindow::MoveByUser(const CPoint& point) {
  if (g_McAppUiFlag_006A1B14 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0xad9);
  }
}

// FUNCTION: IMPERIALISM 0x0048e240
void TWindow::ResizeByUser(const CPoint& point) {
  if (g_McAppUiFlag_006A1B18 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0xaee);
  }
}

// FUNCTION: IMPERIALISM 0x0048e270
void TWindow::ZoomByUser(const CPoint& point, short partCode) {
  if (g_McAppUiFlag_006A1B1C == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0xaff);
  }
}

// FUNCTION: IMPERIALISM 0x0048e2a0
void TWindow::Free() {
  CWnd* window = nativeWindow;
  if (window != 0) {
    if (window->m_hWnd != 0) {
      ::SendMessageA(window->m_hWnd, 0x4ef, 0, controlTag);
      ::SendMessageA(nativeWindow->m_hWnd, 0x468, 4, controlTag);
    } else {
      if (window->IsKindOf(RUNTIME_CLASS(CMcWindow))) {
        CMcWindow* mcWindow = static_cast<CMcWindow*>(nativeWindow);
        mcWindow->AssertValid();
        mcWindow->m_pOwnerWindow = 0;
        delete mcWindow;
      } else {
        delete nativeWindow;
      }
      nativeWindow = 0;
    }
  }
  while (childList != 0) {
    static_cast<TView*>(childList->GetHead())->Free();
  }
  if (ownerContext != 0) {
    ownerContext->RemoveSubView(this);
    ownerContext = 0;
  }
  if (g_pApplication != 0 &&
      static_cast<TEventHandler*>(g_pApplication) != static_cast<TEventHandler*>(this)) {
    if (g_pApplication->GetTarget() == this) {
      TEventHandler* replacement = GetNextHandler();
      if (replacement == 0) {
        g_pApplication->SetTarget(g_pApplication);
      } else {
        g_pApplication->SetTarget(replacement);
      }
    }
  }
  nextHandler = 0;
  if (firstBehavior != 0) {
    firstBehavior->Free();
  }
  firstBehavior = 0;
  delete this;
}

// Dead predicate (no live callers): true when the window's +0x9c flag word is 0x80.
// FUNCTION: IMPERIALISM 0x0048e400
char __cdecl IsWindowFlagsWord0x80(TWindow* window) {
  if (window != 0) {
    return window->windowFlags == 0x80;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00492cc0
TWindow* TWindow::GetWindow() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00492ce0
TView* TWindow::GetRootView() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00492d00
void TWindow::TranslatePointToParentChain4E(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d20
void TWindow::LocalToWindow(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d40
void TWindow::TranslateRectToWindow(CRect* rect) {}

// FUNCTION: IMPERIALISM 0x00492d60
void TWindow::WindowToLocal(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d80
TObject* TWindow::ShallowClone() {
  ReportAssertionFailure(g_szMcAppUiHeaderPath, 0x51e);
  return 0;
}
