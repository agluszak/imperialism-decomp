// Shared base of TView and ApplicationUiRootController. Holds the vtable slots 0x00-0x24
// and fields through +0x1c that both branches inherit (see include/game/TEventHandler.h).
// Bodies here are the original shared implementations referenced by both derived vtables;
// TView/AppRoot override only the few slots where their vtable bodies differ.

#pragma optimize("y", on)
#include "game/TEventHandler.h"
#include "game/TView.h"
#include "game/ApplicationUiRootController.h"

void* TEventHandler::GetTEventHandlerClassNamePointer() {
  return 0;
}

TEventHandler::~TEventHandler() {}

void TEventHandler::vmethod_0002() {}
void TEventHandler::vmethod_0003() {}
void TEventHandler::vmethod_0004() {}
void TEventHandler::vmethod_0005() {}
void TEventHandler::vmethod_0006() {}
// Slot 0x07/0x08: base implementations (overridden by TView and AppRoot).
void TEventHandler::CallVoidSlot1C() {}
void TEventHandler::vmethod_0008() {}
void TEventHandler::vmethod_0009() {}

// FUNCTION: IMPERIALISM 0x0048a240
char TEventHandler::GetBoolSlot28() {
  return (char)field04;
}

// FUNCTION: IMPERIALISM 0x0048a260
void TEventHandler::SetControlValue(int value) {
  field04 = (signed char)value;
}

// FUNCTION: IMPERIALISM 0x0048a2c0
int TEventHandler::QueryStepValue() {
  return field0c;
}

// Dispatch a queued command record: the command's stored handler (cmd+0x10) receives the
// command's payload words (cmd+0x08, cmd+0x0c) plus the command itself, then the command
// is released via slot 0x07.
// FUNCTION: IMPERIALISM 0x0048a3b0
void TEventHandler::vmethod_0013(int* cmd) {
  reinterpret_cast<TView*>(cmd[4])->DispatchEvent(cmd[2], reinterpret_cast<void*>(cmd[3]),
                                                  reinterpret_cast<int>(cmd));
  if (cmd != 0) {
    reinterpret_cast<TView*>(cmd)->CallVoidSlot1C();
  }
}

// FUNCTION: IMPERIALISM 0x0048a3f0
void TEventHandler::vmethod_0014(int command) {
  vmethod_0013(reinterpret_cast<int*>(command));
}

// Forward an event triplet to the child object returned by slot 0x0c (QueryStepValue),
// if any. Derived classes override slot 0x0c to return the active child control.
// FUNCTION: IMPERIALISM 0x0048a280
void TEventHandler::vmethod_0015(int arg1, void* arg2, int arg3) {
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->DispatchEvent(arg1, arg2, arg3);
  }
}

// FUNCTION: IMPERIALISM 0x0048a2e0
void TEventHandler::DispatchEvent(int arg1, void* arg2, int arg3) {
  vmethod_0015(arg1, arg2, arg3);
}

// FUNCTION: IMPERIALISM 0x0048a310
void TEventHandler::vmethod_0017(int param) {
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->vmethod_0017(param);
  }
}

// FUNCTION: IMPERIALISM 0x0048a380
void TEventHandler::ForwardParam(int param) {
  TView* child = reinterpret_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->ForwardParam(param);
  }
}

// FUNCTION: IMPERIALISM 0x0048a480
char TEventHandler::vmethod_0019() {
  return 0;
}

void TEventHandler::vmethod_0020() {}
void TEventHandler::vmethod_0021() {}

// Slot 0x16: base implementation (TView overrides with the owner-chain walk).
class TView* TEventHandler::OwnerPanel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a530
char TEventHandler::vmethod_0023() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a550
char TEventHandler::vmethod_0024() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a690
void TEventHandler::vmethod_0025() {}

// FUNCTION: IMPERIALISM 0x0048a6b0
void TEventHandler::vmethod_0026(int gate) {
  (void)gate;
}

void TEventHandler::vmethod_0027() {}
void TEventHandler::vmethod_0028() {}
void TEventHandler::vmethod_0029() {}
void TEventHandler::vmethod_0030() {}

// Make this view the active view if allowed: already-active short-circuits to true;
// otherwise the current active view must agree (slot 0x20) before we take over.
// FUNCTION: IMPERIALISM 0x0048a570
char TEventHandler::vmethod_0031() {
  TView* active = g_pApplicationUiRootController->GetActiveView();
  if (this == active) {
    return 1;
  }
  if (active != 0 && active->vmethod_0080() != 0) {
    g_pApplicationUiRootController->SetActiveView(reinterpret_cast<TView*>(this));
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a5e0
char TEventHandler::vmethod_0080() {
  if (g_pApplicationUiRootController == 0) {
    return 0;
  }
  TView* activeView = g_pApplicationUiRootController->GetActiveView();
  if (activeView == 0) {
    return 0;
  }
  char gate = activeView->vmethod_0024();
  if (gate == 0) {
    activeView->vmethod_0025();
    g_pApplicationUiRootController->SetActiveView(
        reinterpret_cast<TView*>(g_pApplicationUiRootController));
    return 1;
  }
  activeView->vmethod_0026(gate);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a710
void TEventHandler::vmethod_0081() {}

// True iff this view is the root controller's current active view.
// FUNCTION: IMPERIALISM 0x0048a500
char TEventHandler::vmethod_0032() {
  return this == g_pApplicationUiRootController->GetActiveView();
}

// If the given object is our currently-linked field18 target, detach it both ways.
// FUNCTION: IMPERIALISM 0x0048a4a0
void TEventHandler::vmethod_0033(int arg) {
  if (field18 != 0 && field18 == arg) {
    field18 = 0;
    *reinterpret_cast<int*>(arg + 8) = 0;
  }
}

// Link this view to a resource-owner object and set the owner's back-pointer to this.
// FUNCTION: IMPERIALISM 0x0048a4d0
void TEventHandler::SetUiResourceOwner(int owner) {
  if (owner != 0) {
    field18 = owner;
    *reinterpret_cast<int*>(owner + 8) = reinterpret_cast<int>(this);
  }
}
