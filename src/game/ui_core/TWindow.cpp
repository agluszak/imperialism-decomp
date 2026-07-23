#include "game/ui_core/TWindow.h"

#include "game/ImperialismApp.h"
#include "game/ui_core/CMcWindow.h"
#include "game/ui_core/TApplication.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/CWMgrIterator.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// One-shot McAppUI invalidation-flag assert. The original reaches the shared invalidation
// helper through the incremental-link thunk; each call site is gated by its own
// g_McAppUiFlag_* one-shot so the assert fires at most once.
static __inline void AssertMcAppUiInvalidation(const char* path, int line) {
  TemporarilyClearAndRestoreUiInvalidationFlag(path, line);
}

// FUNCTION: IMPERIALISM 0x0048d500
TWindow::TWindow() : TView(), dialogBehavior(), busyFlag98(0) {
  g_LiveViewRegistry.AddHead(this);
  dialogBehavior.SetUiColorDescriptorGoldTriplet(1, 0x20202020, 0x20202020);
  activeLinkedWindow64 = this;
  dialogBehavior.SetOwner(this);
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
void TWindow::SetDialogItems(unsigned long defaultCommandCode, unsigned long cancelCommandCode) {
  dialogBehavior.defaultCommandCode = defaultCommandCode;
  dialogBehavior.cancelCommandCode = cancelCommandCode;
}

// FUNCTION: IMPERIALISM 0x0048d8d0
void TWindow::AssertMcAppUILine2358(int) {
  if (g_McAppUiFlag_006A1B04 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0x936);
  }
}

// FUNCTION: IMPERIALISM 0x0048d900
void TWindow::Show(unsigned char show, unsigned char refresh) {
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    WPARAM wParam = show == 0 ? 3 : 2;
    SendMessageA(nativeWindow50->m_hWnd, 0x468, wParam, controlTag);
  }
  if ((int)show != field08) {
    field08 = (int)show;
    if (refresh != 0) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0048d980
bool TWindow::IsActionable() {
  return busyFlag98 != 0 && g_McAppUiActiveFlag_006950AC != 0 && nativeWindow50 != 0 &&
         field08 != 0;
}

// FUNCTION: IMPERIALISM 0x0048d9c0
void TWindow::SetTitle(const CString* title) {
  nativeWindow50->SetWindowText(*title);
}

// FUNCTION: IMPERIALISM 0x0048d9f0
void TWindow::GetTitle(CString* title) {
  nativeWindow50->GetWindowText(*title);
}

// FUNCTION: IMPERIALISM 0x0048da10
unsigned char TWindow::IsModal() {
  TDialogBehavior* behavior = GetDialogBehavior();
  if (behavior != 0) {
    return behavior->armed;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048da40
void TWindow::SetModality(unsigned char modal) {
  dialogBehavior.armed = modal;
}

// Run this window as a modal: optionally arm the dialog-state flag, disable the window
// currently on top of the global modal stack, push self, run the embedded dialog's modal
// loop, then pop self and re-enable the window beneath. Returns the command the dialog
// armed during the loop.
// FUNCTION: IMPERIALISM 0x0048da60
int TWindow::PoseModally() {
  TDialogBehavior* behavior = GetDialogBehavior();
  unsigned char wasArmed = behavior->armed;
  if (wasArmed == 0) {
    SetModality(1);
  }
  if (!g_ModalViewStack.IsEmpty()) {
    TWindow* top = static_cast<TWindow*>(g_ModalViewStack.GetHead());
    top->AssertValid();
    if (top->nativeWindow50 != 0) {
      top->nativeWindow50->EnableWindow(0);
    }
  }
  g_ModalViewStack.AddHead(this);
  behavior->PoseModally(); // slot 0x12: run the modal message loop
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
    SetModality(0);
  }
  g_pImperialismApp->RestoreWaitCursorIfStartupBusy();
  return armedCommand;
}

// FUNCTION: IMPERIALISM 0x0048dc60
unsigned char TWindow::IsDismissed() {
  TDialogBehavior* behavior = GetDialogBehavior();
  if (behavior != 0) {
    return behavior->dismissPending;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0048dc90
void TWindow::Dismiss(unsigned long commandCode, unsigned char accepted) {
  TDialogBehavior* behavior = GetDialogBehavior();
  if (behavior != 0) {
    behavior->Dismiss(commandCode, accepted);
  }
}

// The 0x74 region is constructed as a real TDialogBehavior (ConstructTDialogBehaviorBaseState
// writes its vptr at +0x74); expose it through its real type so callers dispatch real virtuals.
// FUNCTION: IMPERIALISM 0x0048dcc0
TDialogBehavior* TWindow::GetDialogBehavior() {
  return &dialogBehavior;
}

// FUNCTION: IMPERIALISM 0x0048dce0
void TWindow::AssertMcAppUILine2554() {
  if (g_McAppUiFlag_006A1B08 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0x9fa);
  }
}

// FUNCTION: IMPERIALISM 0x0048dd10
void TWindow::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // Direct access to the embedded TDialogBehavior (the original reads its vptr straight from
  // +0x74), then bubble to DoEvent.
  dialogBehavior.DoEvent(commandId, sourceHandler, event);
  DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0048dd50
void TWindow::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0x1a) {
    if (g_McAppUiFlag_006A1B0C == 0) {
      AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xa1a);
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
  if (target != activeLinkedWindow64) {
    activeLinkedWindow64->BecameWindowTarget();
    activeLinkedWindow64 = target;
    target->TargetValidationSucceeded();
  }
}

// Realize and show this window: on first call create the host CMcWindow and propagate the
// UI resource context into every child control, then notify the window, run the
// not-actionable fallback (mark busy, poke the linked window, fire the slot-0x73 chain),
// and finally recurse the realize hook into each child.
// FUNCTION: IMPERIALISM 0x0048de00
CMcWindow* TWindow::Open() {
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
    busyFlag98 = 1;
    if (activeLinkedWindow64 != 0) {
      activeLinkedWindow64->SelectOwner(0);
    }
    Show(1, 1);
  }
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->Open();
    }
  }
  return 0;
}

// Clear the busy flag, notify the host window, recurse the slot-0x28 hook into every child
// control, then run the slot-0x73 state-notify chain.
// FUNCTION: IMPERIALISM 0x0048e060
void TWindow::Close() {
  busyFlag98 = 0;
  if (nativeWindow50 != 0 && nativeWindow50->m_hWnd != 0) {
    SendMessageA(nativeWindow50->m_hWnd, 0x468, 1, controlTag);
  }
  if (childList44 != 0) {
    POSITION pos = childList44->GetHeadPosition();
    while (pos != NULL) {
      TView* child = static_cast<TView*>(childList44->GetNext(pos));
      child->Close();
    }
  }
  Show(0, 1);
}

// FUNCTION: IMPERIALISM 0x0048e120
void TWindow::CloseAndFree() {
  Close();
  Free();
}

// FUNCTION: IMPERIALISM 0x0048e150
void TWindow::Center(unsigned char centerX, unsigned char centerY, unsigned char unused) {
  (void)unused;
  if (nativeWindow50 != 0) {
    nativeWindow50->CenterWindow(0);
    return;
  }
  if (centerX != 0) {
    ownerLocalX = (0x280 - frameWidth34) / 2;
  }
  if (centerY != 0) {
    ownerLocalY = (0x1e0 - frameHeight38) / 2;
  }
}

// FUNCTION: IMPERIALISM 0x0048e1c0
short TWindow::ContainsMouse(const CPoint& point) {
  (void)point;
  return 3;
}

// FUNCTION: IMPERIALISM 0x0048e1e0
void TWindow::GoAwayByUser(const CPoint& point) {
  (void)point;
  if (g_McAppUiFlag_006A1B10 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xac4);
  }
}

// FUNCTION: IMPERIALISM 0x0048e210
void TWindow::MoveByUser(const CPoint& point) {
  (void)point;
  if (g_McAppUiFlag_006A1B14 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xad9);
  }
}

// FUNCTION: IMPERIALISM 0x0048e240
void TWindow::ResizeByUser(const CPoint& point) {
  (void)point;
  if (g_McAppUiFlag_006A1B18 == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xaee);
  }
}

// FUNCTION: IMPERIALISM 0x0048e270
void TWindow::ZoomByUser(const CPoint& point, short partCode) {
  (void)point;
  (void)partCode;
  if (g_McAppUiFlag_006A1B1C == 0) {
    AssertMcAppUiInvalidation(g_szMcAppUiSourcePath_006950B0, 0xaff);
  }
}

// Object teardown: destroy/notify the host CMcWindow, free all child controls, detach from
// the owner, hand off the target slot, release the linked resource-owner target, then delete
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
      static_cast<TEventHandler*>(g_pApplicationUiRootController) !=
          static_cast<TEventHandler*>(this)) {
    if (g_pApplicationUiRootController->GetTarget() == this) {
      TEventHandler* replacement = GetNextHandler();
      if (replacement == 0) {
        g_pApplicationUiRootController->SetTarget(g_pApplicationUiRootController);
      } else {
        g_pApplicationUiRootController->SetTarget(replacement);
      }
    }
  }
  field0c = 0;
  if (firstBehavior != 0) {
    firstBehavior->Free();
  }
  firstBehavior = 0;
  delete this;
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
void TWindow::TranslatePointToParentChain4D(CPoint* point) {}

// FUNCTION: IMPERIALISM 0x00492d40
void TWindow::TranslateRectToWindow(CRect* rect) {}

// FUNCTION: IMPERIALISM 0x00492d60
void TWindow::WindowToLocal(CPoint* point) {
  (void)point;
}

// FUNCTION: IMPERIALISM 0x00492d80
TObject* TWindow::ShallowClone() {
  AssertMcAppUiInvalidation(g_szMcAppUiHeaderPath_006943CC, 0x51e);
  return 0;
}
