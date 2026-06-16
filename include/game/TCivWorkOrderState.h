#pragma once

#include "decomp_types.h"
#include "game/TUnitOrderState.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

// Civilian work-order object (ctor 0x005c28c0 installs vtable 0x0066ee60). The
// ctor open-codes the inlined base init then writes the derived vptr; modeled as
// a real C++ subclass so `new TCivWorkOrderState()` reproduces the original
// operator-new + ctor sequence at the slot-0x32 call site.
// VTABLE: IMPERIALISM 0x0066ee60
class TCivWorkOrderState : public TUnitOrderState {
public:
  short remainingTurns24;   // 0x24
  short completionMarker26; // 0x26

  TCivWorkOrderState();

  void* operator new(unsigned int size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    (void)ptr;
  }

  void InitializeCivWorkOrderState(int nOrderType, int pOwnerContext, int nOrderOwnerNationId);

protected:
  ~TCivWorkOrderState() {}
};
