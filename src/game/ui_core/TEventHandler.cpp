// Shared base of TView and TApplication. Holds the vtable slots 0x00-0x24
// and fields through +0x1c that both branches inherit (see include/game/TEventHandler.h).
// Bodies here are the original shared implementations referenced by both derived vtables;
// TView/AppRoot override only the few slots where their vtable bodies differ.

#include "game/ui_core/TEventHandler.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/TBehavior.h"
#include "game/TEvent.h"
#include "game/ui_core/TCommand.h"
#include "game/core/TFileStream.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TApplication.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/gfx/ui_invalidation_guard.h"
#include <string.h>

// FUNCTION: IMPERIALISM 0x00415d50
int TEventHandler::GetIdleFreq() {
  return field10;
}

// FUNCTION: IMPERIALISM 0x00415d70
void TEventHandler::SetIdleFreq(int value) {
  field10 = value;
}

// SYNTHETIC: IMPERIALISM 0x0048a0a0
// TEventHandler::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048a0e0
// TEventHandler::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEventHandler, TObject)

// 0x0048a100 is the constructor, not a "defaults helper": besides +0xc/+0x10/+0x14/+0x18
// it stores the vptr (MOV [eax],0x6497a0), which only a ctor does. Ghidra's
// InitializeUiResourceEntryBaseHeaderDefaults name was provisional (Hard Rule 6) and the
// method it named has been deleted -- derived ctors reach this as their base ctor.
// It owns an address, so per the constructor-placement decision it stays out-of-line.
// FUNCTION: IMPERIALISM 0x0048a100
TEventHandler::TEventHandler() : field0c(0), field10(0x7fffffff), field14(0), firstBehavior(0) {}

// Destructor is compiler-generated (implicit virtual dtor); the scalar deleting
// destructor at 0x0048a130 is emitted by the compiler from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0048a130
// TEventHandler::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0048a160
TEventHandler::~TEventHandler() {}

// FUNCTION: IMPERIALISM 0x0048a180
void TEventHandler::IEventHandler(TEventHandler* nextHandler) {
  field04 = 1;
  field08 = 1;
  // +0xc is the linkedChildHandler pointer, not an int payload: the Mac oracle types
  // this parameter TEventHandler* and 0x0048a196 stores it straight into that slot.
  linkedChildHandler = nextHandler;
  controlTag = kControlTagSpSpSpSp;
}
// Slot 0x07/0x08: base implementations (overridden by TView and AppRoot).
// FUNCTION: IMPERIALISM 0x0048a1b0
void TEventHandler::Free() {
  if (g_pApplicationUiRootController != 0 && g_pApplicationUiRootController != this) {
    TEventHandler* currentTarget = g_pApplicationUiRootController->GetTarget();
    if (currentTarget == this) {
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

// FUNCTION: IMPERIALISM 0x0048a240
char TEventHandler::IsEnabled() {
  return (char)field04;
}

// FUNCTION: IMPERIALISM 0x0048a260
void TEventHandler::SetEnable(char enabled) {
  field04 = enabled;
}

// Forward a UI command triplet to the child returned by slot 0x0c (GetNextHandler), if any.
// FUNCTION: IMPERIALISM 0x0048a280
void TEventHandler::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TEventHandler* child = GetNextHandler();
  if (child != 0) {
    child->HandleEvent(commandId, sourceHandler, event);
  }
}

// FUNCTION: IMPERIALISM 0x0048a2c0
TEventHandler* TEventHandler::GetNextHandler() {
  return linkedChildHandler;
}

// Bubble a UI command triplet into this handler chain (forwards to DoEvent at slot 0x0f).
// FUNCTION: IMPERIALISM 0x0048a2e0
void TEventHandler::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x0048a310
void TEventHandler::DoMenuCommand(int param) {
  TEventHandler* child = GetNextHandler();
  if (child != 0) {
    child->DoMenuCommand(param);
  }
}

// FUNCTION: IMPERIALISM 0x0048a340
void TEventHandler::HandleMenuCommand(int command) {
  DoMenuCommand(command);
}

// FUNCTION: IMPERIALISM 0x0048a360
void TEventHandler::HandleKeyEvent(TToolboxEvent* event) {
  DoKeyEvent(event);
}

// FUNCTION: IMPERIALISM 0x0048a380
void TEventHandler::DoKeyEvent(TToolboxEvent* event) {
  TEventHandler* child = GetNextHandler();
  if (child != 0) {
    child->DoKeyEvent(event);
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
  command->targetHandler->HandleEvent(command->dispatchMessage, command->sourceHandler, command);
  if (command != 0) {
    command->Free();
  }
}

// FUNCTION: IMPERIALISM 0x0048a3f0
void TEventHandler::DispatchUiSelectionToHandler(void* payload) {
  DispatchQueuedUiCommandAndRelease(payload);
}

// MacApp TEventHandler::HandleIdle(IdlePhase): throttled idle dispatch, driven for every
// installed cohandler by TApplication::Idle (0x486b10). field10 is the idle frequency in
// tick16 units (0x7fffffff = never; MacApp fIdleFreq) and field14 the last-idle stamp
// (MacApp fLastIdle). Slot 0x13 (DoIdle — MacApp's DoIdle) does
// the work; a zero return on the continue phase (1) re-stamps the throttle clock.
// FUNCTION: IMPERIALISM 0x0048a410
void TEventHandler::HandleIdle(int idlePhase) {
  if (field10 == 0x7fffffff) {
    return;
  }
  if (!IsEnabled()) {
    return;
  }
  if (idlePhase == 1) {
    int now = GetTickCountDiv16();
    if (now - field14 < field10) {
      return;
    }
  }
  if (!DoIdle(idlePhase) && idlePhase == 1) {
    field14 = GetTickCountDiv16();
  }
}

// FUNCTION: IMPERIALISM 0x0048a480
char TEventHandler::DoIdle(int action) {
  (void)action;
  return 0;
}

// Slot 0x23: if the given object is our currently-linked resourceOwner target, detach it
// both ways (inverse of SetUiResourceOwner at slot 0x24).
// FUNCTION: IMPERIALISM 0x0048a4a0
void TEventHandler::RemoveBehavior(TBehavior* behavior) {
  if (firstBehavior != 0 && firstBehavior == behavior) {
    firstBehavior = 0;
    behavior->owner = 0;
  }
}

// Link this view to a resource-owner object and set the owner's back-pointer to this.
// FUNCTION: IMPERIALISM 0x0048a4d0
void TEventHandler::AddBehavior(TBehavior* behavior) {
  if (behavior != 0) {
    firstBehavior = behavior;
    behavior->owner = this;
  }
}

// True iff this view is the root controller's current target.
// FUNCTION: IMPERIALISM 0x0048a500
char TEventHandler::IsTarget() {
  return this == g_pApplicationUiRootController->GetTarget();
}

// FUNCTION: IMPERIALISM 0x0048a530
char TEventHandler::WantsToBeTarget() {
  return 0;
}

// Slot 0x18: veto gate consulted by ResignTarget before the target is torn
// down. 0 == no objection (base default); a nonzero code blocks deactivation and is echoed
// back through TargetValidationFailed.
// FUNCTION: IMPERIALISM 0x0048a550
char TEventHandler::WillingToResignTarget() {
  return 0;
}

// Make this view the target if allowed: already-active short-circuits to true;
// otherwise the current target must agree (slot 0x20) before we take over.
// FUNCTION: IMPERIALISM 0x0048a570
char TEventHandler::BecomeTarget() {
  TEventHandler* active = g_pApplicationUiRootController->GetTarget();
  if (this == active) {
    return 1;
  }
  if (active != 0 && active->ResignTarget() != 0) {
    g_pApplicationUiRootController->SetTarget(this);
    return 1;
  }
  return 0;
}

// Slot 0x20: ask the root controller's current target to relinquish. It consults the
// target's WillingToResignTarget: no veto -> notify it via ResignedTarget, hand the
// active slot back to the root controller, and report success; otherwise notify the active
// view via TargetValidationFailed(reason) and report failure. Called by
// BecomeTarget on the incumbent before a new view takes over.
// FUNCTION: IMPERIALISM 0x0048a5e0
char TEventHandler::ResignTarget() {
  if (g_pApplicationUiRootController == 0) {
    return 0;
  }
  TEventHandler* currentTarget = g_pApplicationUiRootController->GetTarget();
  if (currentTarget == 0) {
    return 0;
  }
  char gate = currentTarget->WillingToResignTarget();
  if (gate == 0) {
    currentTarget->ResignedTarget();
    g_pApplicationUiRootController->SetTarget(g_pApplicationUiRootController);
    return 1;
  }
  currentTarget->TargetValidationFailed(gate);
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048a650
void TEventHandler::TargetValidationSucceeded() {}

// FUNCTION: IMPERIALISM 0x0048a670
void TEventHandler::ResignedWindowTarget() {
  HandleEvent(0x1a, this, 0);
}

// Slot 0x19: notification hook fired on the target when ResignTarget is
// letting it go (base is a no-op).
// FUNCTION: IMPERIALISM 0x0048a690
void TEventHandler::ResignedTarget() {}

// Slot 0x1a: notification hook fired on the target when its own WillingToResignTarget
// blocked deactivation, passed the veto reason (base is a no-op).
// FUNCTION: IMPERIALISM 0x0048a6b0
void TEventHandler::TargetValidationFailed(int gate) {
  (void)gate;
}

// FUNCTION: IMPERIALISM 0x0048a6d0
void TEventHandler::BecameWindowTarget() {
  HandleEvent(0x19, this, 0);
}

// Notify the handler chain that this object became the target.
// FUNCTION: IMPERIALISM 0x0048a6f0
void TEventHandler::BecameTarget() {
  HandleEvent(0x1b, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a710
void TEventHandler::SelectOwner(unsigned char) {}

// Slot 0x16: base implementation (TView overrides with the owner-chain walk).
// FUNCTION: IMPERIALISM 0x0048a730
TWindow* TEventHandler::GetWindow() {
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

// FUNCTION: IMPERIALISM 0x005d4b30
void QueueDeferredUiEventPacket(TView* owner, int commandId, TView* control) {
  TEvent* event = new TEvent();
  event->commandNumber = commandId;
  event->dispatchMessage = commandId;
  event->sourceHandler = control;
  event->targetHandler = owner;
  owner->DispatchQueuedUiCommandAndRelease(event);
}
