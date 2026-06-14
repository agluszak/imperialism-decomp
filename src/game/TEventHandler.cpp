// Shared base of TView and ApplicationUiRootController. Holds the vtable slots 0x00-0x24
// and fields through +0x1c that both branches inherit (see include/game/TEventHandler.h).
// Bodies here are the original shared implementations referenced by both derived vtables;
// TView/AppRoot override only the few slots where their vtable bodies differ.

#pragma optimize("y", on)
#include "game/CRuntimeClass.h"
#include "game/CObject.h"
#include "game/TEventHandler.h"
#include "game/TEvent.h"
#include "game/TView.h"
#include "game/ApplicationUiRootController.h"
#include "game/mcappui_globals.h"

extern "C" {
extern char PTR_s_TEventHandler_00649588;
}

undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 CreateObject_606ff2(void);

extern ApplicationUiRootController* g_pApplicationUiRootController;

// Drain the linked command/event list rooted at handler+0x04 until field0c reaches zero.
// FUNCTION: IMPERIALISM 0x0048a070
void TEventHandler::CreateTEventHandlerInstance(TEventHandler* handler) {
  while (handler->field0c != 0) {
    TEventHandler* entry = *reinterpret_cast<TEventHandler**>(handler->field04 + 8);
    entry->ReleaseRuntimeSelectionOwnerAndDestroyObject();
  }
}

// FUNCTION: IMPERIALISM 0x0048a0e0
CRuntimeClass* TEventHandler::GetTEventHandlerClassNamePointer() {
  return reinterpret_cast<CRuntimeClass*>(&PTR_s_TEventHandler_00649588);
}

TEventHandler::~TEventHandler() {}

void TEventHandler::vmethod_0002() {}
void TEventHandler::vmethod_0003() {}
void TEventHandler::vmethod_0004() {}
// FUNCTION: IMPERIALISM 0x00485f70
void TEventHandler::HandleCityDialogNoOpSlot14(int arg) {
  (void)arg;
}
// FUNCTION: IMPERIALISM 0x00485f90
void TEventHandler::HandleCityDialogNoOpSlot18(int arg) {
  (void)arg;
}
// Slot 0x07/0x08: base implementations (overridden by TView and AppRoot).
// FUNCTION: IMPERIALISM 0x0048a1b0
void TEventHandler::ReleaseRuntimeSelectionOwnerAndDestroyObject() {
  if (g_pApplicationUiRootController != 0 &&
      g_pApplicationUiRootController != reinterpret_cast<ApplicationUiRootController*>(this)) {
    TView* activeView = g_pApplicationUiRootController->GetActiveView();
    if (activeView == reinterpret_cast<TView*>(this)) {
      TView* replacement = reinterpret_cast<TView*>(QueryStepValue());
      if (replacement == 0) {
        g_pApplicationUiRootController->SetActiveView(
            reinterpret_cast<TView*>(g_pApplicationUiRootController));
      } else {
        g_pApplicationUiRootController->SetActiveView(replacement);
      }
    }
  }
  field0c = 0;
  if (field18 != 0) {
    reinterpret_cast<TEventHandler*>(field18)->ReleaseRuntimeSelectionOwnerAndDestroyObject();
  }
  field18 = 0;
  delete this;
}

// Slot 0x08 base body: allocates a 0x20-byte UI resource entry header (0x48a7c0). TView
// overrides at 0x48bfd0 with CloneEngineerDialogStateToNewInstance.
// FUNCTION: IMPERIALISM 0x0048a7c0
void* TEventHandler::CloneEngineerDialogStateToNewInstance() {
  if (g_McAppUiFlag_006A1AE4 == 0) {
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        g_szMcAppUiSourcePath_006950B0, 0x2ef);
  }
  TEventHandler* header = reinterpret_cast<TEventHandler*>(AllocateWithFallbackHandler(0x20));
  if (header == 0) {
    return 0;
  }
  // MSVC EH partial-construction sentinel sequence (McAppUI.cpp); not ctor emission.
  *reinterpret_cast<void**>(header) = reinterpret_cast<void*>(0x006485c0);
  header->field04 = field04;
  header->field08 = field08;
  header->field0c = field0c;
  header->controlTag = controlTag;
  *reinterpret_cast<void**>(header) = reinterpret_cast<void*>(0x006497a0);
  return header;
}

// Shared vtable slot 0x09 body (also referenced from TZone vtable).
// FUNCTION: IMPERIALISM 0x00415ce0
void* TEventHandler::HandleTurnEventVtableSlot24CopyPayloadBuffer() {
  CRuntimeClass* runtimeClass = GetTEventHandlerClassNamePointer();
  unsigned int payloadSize = static_cast<unsigned int>(runtimeClass->m_nObjectSize);
  GetTEventHandlerClassNamePointer();
  CObject* destObject = reinterpret_cast<CObject*>(CreateObject_606ff2());
  if (destObject == 0) {
    return 0;
  }
  unsigned int* destCursor = reinterpret_cast<unsigned int*>(destObject);
  unsigned int* sourceCursor = reinterpret_cast<unsigned int*>(this);
  unsigned int dwordCount = payloadSize >> 2;
  unsigned int byteRemainder = payloadSize & 3;
  unsigned int dwordIndex;
  for (dwordIndex = dwordCount; dwordIndex != 0; dwordIndex = dwordIndex - 1) {
    *destCursor = *sourceCursor;
    sourceCursor = sourceCursor + 1;
    destCursor = destCursor + 1;
  }
  unsigned char* destByteCursor = reinterpret_cast<unsigned char*>(destCursor);
  unsigned char* sourceByteCursor = reinterpret_cast<unsigned char*>(sourceCursor);
  for (; byteRemainder != 0; byteRemainder = byteRemainder - 1) {
    *destByteCursor = *sourceByteCursor;
    sourceByteCursor = sourceByteCursor + 1;
    destByteCursor = destByteCursor + 1;
  }
  return destObject;
}

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
  reinterpret_cast<TView*>(cmd[4])
      ->DispatchEvent(cmd[2], reinterpret_cast<TEventHandler*>(cmd[3]), reinterpret_cast<TEvent*>(cmd));
  if (cmd != 0) {
    reinterpret_cast<TView*>(cmd)->ReleaseRuntimeSelectionOwnerAndDestroyObject();
  }
}

// FUNCTION: IMPERIALISM 0x0048a3f0
void TEventHandler::vmethod_0014(int command) {
  vmethod_0013(reinterpret_cast<int*>(command));
}

// Forward a UI command triplet to the child returned by slot 0x0c (QueryStepValue), if any.
// FUNCTION: IMPERIALISM 0x0048a280
void TEventHandler::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TEventHandler* child = reinterpret_cast<TEventHandler*>(QueryStepValue());
  if (child != 0) {
    child->DispatchEvent(commandId, sourceHandler, event);
  }
}

// Bubble a UI command triplet into this handler chain (forwards to HandleEvent at slot 0x0f).
// FUNCTION: IMPERIALISM 0x0048a2e0
void TEventHandler::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  HandleEvent(commandId, sourceHandler, event);
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
char TEventHandler::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00415d50
int TEventHandler::GetCityDialogValueDword10() {
  return field10;
}

// FUNCTION: IMPERIALISM 0x00415d70
void TEventHandler::SetCityDialogValueDword10(int value) {
  field10 = value;
}

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

// FUNCTION: IMPERIALISM 0x0048a650
void TEventHandler::HandleCityProductionNoOp() {}

// FUNCTION: IMPERIALISM 0x0048a6d0
void TEventHandler::DispatchUiCommand19ToParent() {
  DispatchEvent(0x19, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a670
void TEventHandler::DispatchCityProductionAction1A() {
  DispatchEvent(0x1a, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a6f0
void TEventHandler::DispatchCityProductionAction1B() {
  DispatchEvent(0x1b, this, 0);
}

// Make this view the active view if allowed: already-active short-circuits to true;
// otherwise the current active view must agree (slot 0x20) before we take over.
// FUNCTION: IMPERIALISM 0x0048a570
char TEventHandler::ActivateCityProductionViewIfAllowed() {
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
