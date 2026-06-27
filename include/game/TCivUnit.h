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
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5c2b40
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5c2b10
  // slot 0x07 Free inherited unchanged (0x5c2680)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void VTableSlot10(int pOwnerContext) override; // slot 0x0a 0x5c2b70
  virtual void DispatchSlot2C() override; // slot 0x0b 0x5c2a90
  virtual void DetachUnitOrderFromOwnerAndReset() override; // slot 0x0c 0x5c2c40
  virtual void SetOrderModeSlot34(int mode, int payload) override; // slot 0x0d 0x5c29f0
  virtual void ResetCivWorkOrderAndRefreshCounters(); // slot 0x0e 0x5c2c60
// === END GENERATED DECLS (TCivUnit) ===
  short remainingTurns24;   // 0x24
  short completionMarker26; // 0x26

  TCivUnit();

  void InitializeCivWorkOrderState(int nOrderType, int pOwnerContext, int nOrderOwnerNationId);
  int IsInIdleSelectionState();
};

// === BEGIN GENERATED (TCivUnit) — refreshed by `just gen-class TCivUnit`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066ee60 (15 slots), object size 0x28, base TUnit
//   slot 0x00  byte 0x00  0x005c28a0  override  GetTUnitClassNamePointer
//   slot 0x01  byte 0x04  0x005c28f0  override  ConstructTUnitBaseState
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x005c2b40  override  SerializeUnitOrderCoreState
//   slot 0x06  byte 0x18  0x005c2b10  override  DeserializeUnitOrderCoreState
//   slot 0x07  byte 0x1c  0x005c2680  inherited UnlinkFromNationOrTerrainOwnerListAndDestroy
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005c2b70  override  OrphanRetStub_005c2610
//   slot 0x0b  byte 0x2c  0x005c2a90  override  NormalizeUnitOrderStateAfterLoad
//   slot 0x0c  byte 0x30  0x005c2c40  override  OrphanRetStub_005c2470
//   slot 0x0d  byte 0x34  0x005c29f0  override  SetUnitOrderTypeAndOwnerIndex
//   slot 0x0e  byte 0x38  0x005c2c60  override  ResetCivWorkOrderAndRefreshCounters
// object size 0x28 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCivUnit) ===
