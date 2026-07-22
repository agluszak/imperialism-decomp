#pragma once

#include "decomp_types.h"
#include "game/TUnit.h"
#include "game/civilian_domain_types.h"

// Civilian work-order object (ctor 0x005c28c0 installs vtable 0x0066ee60). The
// ctor open-codes the inlined base init then writes the derived vptr; modeled as
// a real C++ subclass so `new TCivUnit()` reproduces the original
// operator-new + ctor sequence at the slot-0x32 call site.
// VTABLE: IMPERIALISM 0x0066ee60
class TCivUnit : public TUnit {
public:
  DECLARE_DYNCREATE(TCivUnit)
  virtual ~TCivUnit() override;                          // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;        // slot 0x05 0x5c2b40
  virtual void ReadFrom(TStream* stream) override;       // slot 0x06 0x5c2b10
  virtual void VTableSlot10(int pOwnerContext) override; // slot 0x0a 0x5c2b70
  virtual void ContinueOrders() override;                // slot 0x0b 0x5c2a90
  virtual void DetachUnitOrderFromOwnerAndReset() override;      // slot 0x0c 0x5c2c40
  virtual void SetOrders(UnitOrder order, int payload) override; // slot 0x0d 0x5c29f0
  virtual void ResetCivWorkOrderAndRefreshCounters();            // slot 0x0e 0x5c2c60
  short remainingTurns24;                                        // 0x24
  short completionMarker26;                                      // 0x26

  TCivUnit();

  void ICivUnit(CivilianUnitKind unitKind, int pOwnerContext, int nOrderOwnerNationId);
  CivilianUnitKind GetCivilianUnitKind() const {
    return DecodeCivilianUnitKind(this->orderType);
  }
  int IsInIdleSelectionState();
};

ASSERT_SIZE(TCivUnit, 0x28);
