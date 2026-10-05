#pragma once

#include "compat.h"

#include "game/map/TMinister.h"

// AI interior minister branch.
// VTABLE: IMPERIALISM 0x00650808
class TInteriorMinister : public TMinister {
public:
  // FUNCTION: IMPERIALISM 0x004be230
  ~TInteriorMinister() override {}
  TInteriorMinister() : TMinister(), capabilityFlag14(1), capabilityFlag16(1) {}

  DECLARE_DYNCREATE(TInteriorMinister)
  void IInteriorMinister(TGreatPower* owner);
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short GetRankingCriterionForGP(short nationSlot) override;
  void MakeNewCity(TCity* city) override;
  // Two stack args (RET 0x8; Ghidra reads two shorts). Mac oracle: SetParameters.
  virtual void SetParameters(short firstParameter, short secondParameter); // slot 0x12 0x4be450
  // Zeroes persistedReservedTable (+0x18..0x25, 7 shorts). 0x4be4f0, __thiscall, no args.
  virtual void ClearPersistedReservedTable();
  virtual void SetCityPolicies();
  virtual void FillOrders();
  virtual short GetNumShipsToBuild(); // 0x16 0x4be480
  virtual short GetNumCarsToBuild(); // 0x17 0x4be4c0
  virtual char DoIncreasedTransport(); // 0x18 0x4be650
  virtual void AdvanceNeedTargetRoundRobin(); // 0x19 0x4be690
  virtual void PleaseBuildShip(short orderKind);    // 0x1a 0x4be3f0
  virtual void IndustryOrder(short industrySlot);   // 0x1b 0x4be410
  virtual void PleaseBuildLandUnit(short unitType); // 0x1c 0x4be430, Mac oracle
  virtual short GetExteriorNeedFor(int orderType);    // 0x1d 0x4be150
  virtual short GetHistoricalNeedFor(int orderType);  // 0x1e 0x4be170
  virtual void ResetHistoricalNeedFor(int orderType); // 0x1f 0x4be190

  short field10;          // +0x10 — set from SetParameters' second argument
  short field12;          // +0x12 — set from SetParameters' first argument
  short capabilityFlag14; // +0x14
  short capabilityFlag16; // +0x16
  short persistedReservedTable[7];
  // +0x26..+0x28: zero field-xrefs; genuinely untouched, not an unrecovered field.
  unsigned char unused26[0x28 - 0x26];
};
ASSERT_SIZE(TInteriorMinister, 0x28);
