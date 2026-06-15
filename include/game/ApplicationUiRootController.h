#pragma once

#include "decomp_types.h"
#include "game/ApplicationUiRootEmbeddedList.h"
#include "game/TEventHandler.h"

class TView;

// Application UI root controller — global modal-view gatekeeper installed at startup.
// Inherits the shared 37-slot base interface (indices 0x00-0x24) and fields through +0x1c
// from TEventHandler (the same base TView derives from). Introduces its own slots 0x25-0x2a
// (byte offsets 0x94-0xa8): a command-handler dispatch, the active-view get/set pair, a
// viewport-edge auto-scroll no-op, an intrusive-list insert/remove, and a per-entry tick
// walk over the embedded list at +0x2c (secondary vtable 0x00648ca8). Size 0x48.
// VTABLE: IMPERIALISM 0x00648bd8
class ApplicationUiRootController : public TEventHandler {
public:
  ApplicationUiRootController();
  ~ApplicationUiRootController() override;

  // vtable index 0x00 override (0x00486740): returns the TApplication CRuntimeClass.
  virtual CRuntimeClass* GetRuntimeClass() const override;

  // vtable index 0x25 (0x00486650): dispatch the queued command-handler argument by
  // calling its vtable slot 0x0b then its slot 0x07 (release/destroy). DEFERRED: the
  // argument's real type is a TCommandHandler descendant (not yet recovered as a class),
  // and its slot 0x0b is a no-arg command-processing method distinct from TEventHandler's
  // slot-0x0b SetControlValue(int). Porting this correctly needs TCommandHandler recovery
  // first; kept as a placeholder so the vtable layout stays correct.
  virtual void vmethod_0037();
  // vtable index 0x26 (0x00486880): store the active modal view pointer.
  virtual void SetActiveView(TView* view);
  // vtable index 0x27 (0x004868a0): load the active modal view pointer.
  virtual TView* GetActiveView();
  // vtable index 0x28 (0x00486990): viewport-edge auto-scroll hook; no-op in the original
  // (RET 0xc — takes 3 stack args). Kept as a real virtual so descendants can override.
  virtual void HandleTurnEventViewportEdgeAutoScroll(int arg1, int arg2, int arg3);
  // vtable index 0x29 (0x004869b0): when insertFlag is nonzero, allocate (or reuse from
  // the free list) a 12-byte node, store `value` at node+8, and link it at the list head;
  // when zero, find the first node whose node+8 equals `value`, unlink it, and return the
  // node to the free list (freeing the block chain when the list becomes empty).
  virtual void InsertOrRemoveTrackedEntry(int value, char insertFlag);
  // vtable index 0x2a (0x00486b10): walk the embedded list and invoke each entry's tick
  // method (slot at node+8 receiver, passing arg) via the per-entry thunk.
  virtual void TickEachTrackedEntry(int arg);

  TView* activeView;                          // 0x20
  int screenModeAt24;                         // 0x24
  int field28;                                // 0x28
  ApplicationUiRootEmbeddedList embeddedList; // 0x2c
};

extern ApplicationUiRootController* g_pApplicationUiRootController;
