#pragma once

#include "decomp_types.h"
#include "game/TUnit.h"

// Civilian work-order object (ctor 0x005c28c0 installs vtable 0x0066ee60). The
// ctor open-codes the inlined base init then writes the derived vptr; modeled as
// a real C++ subclass so `new TCivUnit()` reproduces the original
// operator-new + ctor sequence at the slot-0x32 call site.
// VTABLE: IMPERIALISM 0x0066ee60
class TCivUnit : public TUnit {
public:
  // === BEGIN GENERATED DECLS (TCivUnit) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TCivUnit)
  virtual ~TCivUnit() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5c2b40
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5c2b10
  // slot 0x07 Free inherited unchanged (0x5c2680)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void VTableSlot10(int pOwnerContext) override;           // slot 0x0a 0x5c2b70
  virtual void DispatchSlot2C() override;                          // slot 0x0b 0x5c2a90
  virtual void DetachUnitOrderFromOwnerAndReset() override;        // slot 0x0c 0x5c2c40
  virtual void SetOrderModeSlot34(int mode, int payload) override; // slot 0x0d 0x5c29f0
  virtual void ResetCivWorkOrderAndRefreshCounters();              // slot 0x0e 0x5c2c60
  // === END GENERATED DECLS (TCivUnit) ===
  short remainingTurns24;   // 0x24
  short completionMarker26; // 0x26

  TCivUnit();

  void InitializeCivWorkOrderState(int nOrderType, int pOwnerContext, int nOrderOwnerNationId);
  int IsInIdleSelectionState();
};

ASSERT_SIZE(TCivUnit, 0x28);
