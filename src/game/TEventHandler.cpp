// Shared base of TView and TApplication. Holds the vtable slots 0x00-0x24
// and fields through +0x1c that both branches inherit (see include/game/TEventHandler.h).
// Bodies here are the original shared implementations referenced by both derived vtables;
// TView/AppRoot override only the few slots where their vtable bodies differ.

#include "game/TEventHandler.h"
#include "game/TEvent.h"
#include "game/TCommand.h"
#include "game/TFileStream.h"
#include "game/TView.h"
#include "game/TApplication.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include <string.h>

extern "C" {
extern CRuntimeClass PTR_s_TEventHandler_00649588;
}

// FUNCTION: IMPERIALISM 0x00415d50
int TEventHandler::GetCityDialogValueDword10() {
  return field10;
}

// FUNCTION: IMPERIALISM 0x00415d70
void TEventHandler::SetCityDialogValueDword10(int value) {
  field10 = value;
}

// Drain the linked command/event list rooted at handler+0x04 until field0c reaches zero.
// FUNCTION: IMPERIALISM 0x0048a070
void TEventHandler::CreateTEventHandlerInstance() {
  while (field0c != 0) {
    TEventHandler* entry = static_cast<TEventHandler*>(recordHead->payload);
    entry->Free();
  }
}
// SYNTHETIC: IMPERIALISM 0x0048a0a0
// TEventHandler::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048a0e0
// TEventHandler::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEventHandler, TObject)

TEventHandler::TEventHandler() : field0c(0), field10(0x7fffffff), field14(0), resourceOwner(0) {}

// Binary helper @ 0x48a100: same header field defaults as TEventHandler().
// FUNCTION: IMPERIALISM 0x0048a100
void TEventHandler::InitializeUiResourceEntryBaseHeaderDefaults() {
  field0c = 0;
  field10 = 0x7fffffff;
  field14 = 0;
}

// FUNCTION: IMPERIALISM 0x0048a180
void TEventHandler::InitializePacketHeaderFields_Tag20202020(int packetTag) {
  field04 = 1;
  field08 = 1;
  field0c = packetTag;
  controlTag = 0x20202020;
}

// Destructor is compiler-generated (implicit virtual dtor); the scalar deleting
// destructor at 0x0048a130 is emitted by the compiler from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0048a130
// TEventHandler::`scalar deleting destructor'

TEventHandler::~TEventHandler() {}
// Slot 0x07/0x08: base implementations (overridden by TView and AppRoot).
// FUNCTION: IMPERIALISM 0x0048a1b0
void TEventHandler::Free() {
  if (g_pApplicationUiRootController != 0 && g_pApplicationUiRootController != this) {
    TEventHandler* activeView = g_pApplicationUiRootController->GetActiveView();
    if (activeView == this) {
      TEventHandler* replacement = QueryStepValue();
      if (replacement == 0) {
        g_pApplicationUiRootController->SetActiveView(g_pApplicationUiRootController);
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

// FUNCTION: IMPERIALISM 0x0048a240
char TEventHandler::GetBoolSlot28() {
  return (char)field04;
}

// FUNCTION: IMPERIALISM 0x0048a260
void TEventHandler::SetControlValue(int value) {
  field04 = (signed char)value;
}

// Forward a UI command triplet to the child returned by slot 0x0c (QueryStepValue), if any.
// FUNCTION: IMPERIALISM 0x0048a280
void TEventHandler::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TEventHandler* child = QueryStepValue();
  if (child != 0) {
    child->DispatchEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048a2c0
TEventHandler* TEventHandler::QueryStepValue() {
  return linkedChildHandler;
}

// Bubble a UI command triplet into this handler chain (forwards to HandleEvent at slot 0x0f).
// FUNCTION: IMPERIALISM 0x0048a2e0
void TEventHandler::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0048a310
void TEventHandler::vmethod_0017(int param) {
  TView* child = static_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->vmethod_0017(param);
  }
}

// FUNCTION: IMPERIALISM 0x0048a380
void TEventHandler::ForwardParam(int param) {
  TView* child = static_cast<TView*>(QueryStepValue());
  if (child != 0) {
    child->ForwardParam(param);
  }
}

// Dispatch a queued command record: the command's stored handler (cmd+0x10) receives the
// command's payload words (cmd+0x08, cmd+0x0c) plus the command itself, then the command
// is released via slot 0x07.
// FUNCTION: IMPERIALISM 0x0048a3b0
void TEventHandler::DispatchQueuedUiCommandAndRelease(void* payload) {
  // Polymorphic dispatch slot: this base interprets the opaque payload as a TCommand
  // (other overrides interpret it differently, e.g. TView passes a RECT). The target
  // handler dispatches the command's message + source handler, with the command object
  // itself passed through its real TEvent base, then frees it.
  TCommand* command = static_cast<TCommand*>(payload);
  command->targetHandler->DispatchEvent(command->dispatchMessage, command->sourceHandler, command);
  if (command != 0) {
    command->Free();
  }
}

// FUNCTION: IMPERIALISM 0x0048a3f0
void TEventHandler::DispatchUiSelectionToHandler(void* payload) {
  DispatchQueuedUiCommandAndRelease(payload);
}

// FUNCTION: IMPERIALISM 0x0048a480
char TEventHandler::CanHandleCityDialogActionFalse(int action) {
  (void)action;
  return 0;
}

// If the given object is our currently-linked resourceOwner target, detach it both ways.
// FUNCTION: IMPERIALISM 0x0048a4a0
void TEventHandler::vmethod_0033(TEventHandler* owner) {
  if (linkedResourceOwner != 0 && linkedResourceOwner == owner) {
    linkedResourceOwner = 0;
    owner->resourceOwnerBackLink = 0;
  }
}

// Link this view to a resource-owner object and set the owner's back-pointer to this.
// FUNCTION: IMPERIALISM 0x0048a4d0
void TEventHandler::SetUiResourceOwner(TEventHandler* owner) {
  if (owner != 0) {
    linkedResourceOwner = owner;
    owner->resourceOwnerBackLink = this;
  }
}

// True iff this view is the root controller's current active view.
// FUNCTION: IMPERIALISM 0x0048a500
char TEventHandler::vmethod_0032() {
  return this == g_pApplicationUiRootController->GetActiveView();
}

// FUNCTION: IMPERIALISM 0x0048a530
char TEventHandler::vmethod_0023() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a550
char TEventHandler::vmethod_0024() {
  return 0;
}

// Make this view the active view if allowed: already-active short-circuits to true;
// otherwise the current active view must agree (slot 0x20) before we take over.
// FUNCTION: IMPERIALISM 0x0048a570
char TEventHandler::ActivateCityProductionViewIfAllowed() {
  TEventHandler* active = g_pApplicationUiRootController->GetActiveView();
  if (this == active) {
    return 1;
  }
  if (active != 0 && active->vmethod_0080() != 0) {
    g_pApplicationUiRootController->SetActiveView(this);
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a5e0
char TEventHandler::vmethod_0080() {
  if (g_pApplicationUiRootController == 0) {
    return 0;
  }
  TEventHandler* activeView = g_pApplicationUiRootController->GetActiveView();
  if (activeView == 0) {
    return 0;
  }
  char gate = activeView->vmethod_0024();
  if (gate == 0) {
    activeView->vmethod_0025();
    g_pApplicationUiRootController->SetActiveView(g_pApplicationUiRootController);
    return 1;
  }
  activeView->vmethod_0026(gate);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a650
void TEventHandler::HandleCityProductionNoOp() {}

// FUNCTION: IMPERIALISM 0x0048a670
void TEventHandler::DispatchCityProductionAction1A() {
  DispatchEvent(0x1a, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a690
void TEventHandler::vmethod_0025() {}

// FUNCTION: IMPERIALISM 0x0048a6b0
void TEventHandler::vmethod_0026(int gate) {
  (void)gate;
}

// FUNCTION: IMPERIALISM 0x0048a6d0
void TEventHandler::DispatchUiCommand19ToParent() {
  DispatchEvent(0x19, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a6f0
void TEventHandler::DispatchCityProductionAction1B() {
  DispatchEvent(0x1b, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a710
void TEventHandler::vmethod_0081(int) {}

// Slot 0x16: base implementation (TView overrides with the owner-chain walk).
// FUNCTION: IMPERIALISM 0x0048a730
class TView* TEventHandler::OwnerPanel() {
  return 0;
}

// Slot 0x08 base body: allocates a 0x20-byte UI resource entry header (0x48a7c0). TView
// overrides at 0x48bfd0 with CloneEngineerDialogStateToNewInstance.
// FUNCTION: IMPERIALISM 0x0048a7c0
TObject* TEventHandler::ShallowClone() {
  if (g_McAppUiFlag_006A1AE4 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag();
  }
  TEventHandler* header = new TEventHandler();
  if (header == 0) {
    return 0;
  }
  header->field04 = field04;
  header->field08 = field08;
  header->field0c = field0c;
  header->controlTag = controlTag;
  return header;
}
