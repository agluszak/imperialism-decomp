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
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/gfx/ui_invalidation_guard.h"
#include <string.h>

// FUNCTION: IMPERIALISM 0x00415d50
int TEventHandler::GetIdleFreq() {
  return idleFrequencyTicks;
}

// FUNCTION: IMPERIALISM 0x00415d70
void TEventHandler::SetIdleFreq(int value) {
  idleFrequencyTicks = value;
}

IMPLEMENT_DYNCREATE(TEventHandler, TObject)

// MATCH: this address-owning base constructor stays out-of-line.
// FUNCTION: IMPERIALISM 0x0048a100
TEventHandler::TEventHandler()
    : nextHandler(0), idleFrequencyTicks(0x7fffffff), lastIdleTick(0), firstBehavior(0) {}

// Destructor is compiler-generated (implicit virtual dtor); the scalar deleting
// destructor at 0x0048a130 is emitted by the compiler from real inheritance.

// FUNCTION: IMPERIALISM 0x0048a180
void TEventHandler::IEventHandler(TEventHandler* nextHandler) {
  enabled = 1;
  viewEnabled = 1;
  this->nextHandler = nextHandler;
  controlTag = kControlTagSpSpSpSp;
}
// Slot 0x07/0x08: base implementations (overridden by TView and AppRoot).
// FUNCTION: IMPERIALISM 0x0048a1b0
void TEventHandler::Free() {
  if (g_pApplication != 0 && g_pApplication != this) {
    TEventHandler* currentTarget = g_pApplication->GetTarget();
    if (currentTarget == this) {
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

// FUNCTION: IMPERIALISM 0x0048a240
char TEventHandler::IsEnabled() {
  return (char)enabled;
}

// FUNCTION: IMPERIALISM 0x0048a260
void TEventHandler::SetEnable(char enabled) {
  this->enabled = enabled;
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
  return nextHandler;
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

// FUNCTION: IMPERIALISM 0x0048a3b0
void TEventHandler::DispatchQueuedUiCommandAndRelease(void* payload) {
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

// FUNCTION: IMPERIALISM 0x0048a410
void TEventHandler::HandleIdle(int idlePhase) {
  if (idleFrequencyTicks == 0x7fffffff) {
    return;
  }
  if (!IsEnabled()) {
    return;
  }
  if (idlePhase == 1) {
    int now = GetTickCountDiv16();
    if (now - lastIdleTick < idleFrequencyTicks) {
      return;
    }
  }
  if (!DoIdle(idlePhase) && idlePhase == 1) {
    lastIdleTick = GetTickCountDiv16();
  }
}

// FUNCTION: IMPERIALISM 0x0048a480
bool TEventHandler::DoIdle(int action) {
  return false;
}

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
bool TEventHandler::IsTarget() {
  return this == g_pApplication->GetTarget();
}

// FUNCTION: IMPERIALISM 0x0048a530
bool TEventHandler::WantsToBeTarget() {
  return false;
}

// FUNCTION: IMPERIALISM 0x0048a550
bool TEventHandler::WillingToResignTarget() {
  return false;
}

// FUNCTION: IMPERIALISM 0x0048a570
bool TEventHandler::BecomeTarget() {
  TEventHandler* active = g_pApplication->GetTarget();
  if (this == active) {
    return true;
  }
  if (active != 0 && active->ResignTarget()) {
    g_pApplication->SetTarget(this);
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x0048a5e0
bool TEventHandler::ResignTarget() {
  if (g_pApplication == 0) {
    return false;
  }
  TEventHandler* currentTarget = g_pApplication->GetTarget();
  if (currentTarget == 0) {
    return false;
  }
  char gate = currentTarget->WillingToResignTarget();
  if (gate == 0) {
    currentTarget->ResignedTarget();
    g_pApplication->SetTarget(g_pApplication);
    return true;
  }
  currentTarget->TargetValidationFailed(gate);
  return false;
}

// FUNCTION: IMPERIALISM 0x0048a650
void TEventHandler::TargetValidationSucceeded() {}

// FUNCTION: IMPERIALISM 0x0048a670
void TEventHandler::ResignedWindowTarget() {
  HandleEvent(0x1a, this, 0);
}

// FUNCTION: IMPERIALISM 0x0048a690
void TEventHandler::ResignedTarget() {}

// FUNCTION: IMPERIALISM 0x0048a6b0
void TEventHandler::TargetValidationFailed(int gate) {}

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

// FUNCTION: IMPERIALISM 0x0048a790
void TEventHandler::CopyHandlerFieldsFrom(const TEventHandler* source) {
  enabled = source->enabled;
  viewEnabled = source->viewEnabled;
  controlTag = source->controlTag;
  nextHandler = source->nextHandler;
}

// FUNCTION: IMPERIALISM 0x0048a7c0
TObject* TEventHandler::ShallowClone() {
  if (g_McAppUiFlag_006A1AE4 == 0) {
    ReportAssertionFailure(g_szMcAppUiSourcePath, 0x2ef);
  }
  TEventHandler* header = new TEventHandler();
  if (header == 0) {
    return 0;
  }
  header->enabled = enabled;
  header->viewEnabled = viewEnabled;
  header->nextHandler = nextHandler;
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
