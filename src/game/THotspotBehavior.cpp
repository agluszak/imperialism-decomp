#include "game/THotspotBehavior.h"

#include "game/TEvent.h"
#include "game/TView.h"
#include "game/ui_tags_common.h"
// SYNTHETIC: IMPERIALISM 0x004b0af0
// THotspotBehavior::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b0b60
// THotspotBehavior::GetRuntimeClass

IMPLEMENT_DYNCREATE(THotspotBehavior, TBehavior)

// FUNCTION: IMPERIALISM 0x004b0b80
THotspotBehavior::THotspotBehavior() : TBehavior() {}

// SYNTHETIC: IMPERIALISM 0x004b0bb0
// THotspotBehavior::`scalar deleting destructor'
THotspotBehavior::~THotspotBehavior() {}

// FUNCTION: IMPERIALISM 0x004b0c00
unsigned char THotspotBehavior::DoSetCursor(CPoint* point, RgnHandle region) {
  (void)point;
  (void)region;
  TView* target = static_cast<TView*>(owner);
  if (target->controlTag != kControlTagDialog && target->controlTag != kControlTagMain) {
    target = target->ownerContext;
  }

  TEvent* event = new TEvent();
  event->commandNumber = 0x6b;
  event->dispatchMessage = 0x6b;
  event->sourceHandler = owner;
  event->targetHandler = target;
  target->DispatchQueuedUiCommandAndRelease(event);
  return 0;
}
