#pragma once

#include "compat.h"

#include "game/map/TMinister.h"

// AI interior minister branch.
// VTABLE: IMPERIALISM 0x00650808
class TInteriorMinister : public TMinister {
public:
  // FUNCTION: IMPERIALISM 0x004be230
  ~TInteriorMinister() override {}
  // In-class so VC5 can inline the immediate TMinister construction into concrete
  // city-minister constructors; it also emits the original standalone copy.
  // FUNCTION: IMPERIALISM 0x004be1d0
  TInteriorMinister() : TMinister(), capabilityFlag14(1), capabilityFlag16(1) {}

  DECLARE_DYNCREATE(TInteriorMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short GetRankingCriterionForGP(short nationSlot) override;
  void MakeNewCity(TCity* city) override;
  // Two stack args (RET 0x8; Ghidra reads two shorts). Mac oracle: SetParameters.
  virtual void SetParameters(short firstParameter, short secondParameter); // slot 0x12 0x4be450
  // Zeroes trailingTable (+0x18..0x25, 7 shorts). 0x4be4f0, __thiscall, no args.
  virtual void ClearTrailingTable();
  // Tops up up to 10 of the nation's needs (fixed priority order
  // g_aInteriorMinisterNeedPriorityOrder_00696408) toward their current reading,
  // stopping when need-cap headroom hits zero. Mac oracle name (present on both
  // TInteriorMinister and TCityInteriorMinister); both call sites run it right after
  // RebuildNationResourceYieldCountersAndDevelopmentTargets on city creation /
  // population change. slot 0x14 0x4be520
  virtual void SetCityPolicies();
  // Runs DoIncreasedTransport() once per GetNumCarsToBuild() (re-read each iteration); then,
  // once the owner's IsNationResourceNeedCurrentSumExceedingCapA6() is true, decays
  // relation-need scores via the owner's TryDecayRelationNeedScores9AndB() once per
  // GetNumShipsToBuild(), accumulating the results; finally runs AdvanceNeedTargetRoundRobin() that
  // many times. 0x4be5b0, __thiscall, no args.
  virtual void FillOrders();
  // Slots 0x16-0x1f: TInteriorMinister's own new virtuals (real vtable 0x650808 is
  // 32 slots, 0x00-0x1f). TCityInteriorMinister inherits 0x16-0x19 and overrides
  // 0x1a-0x1f.
  // Count of merchant ships to build this pass (used as FillOrders' second loop
  // bound): clamps/returns capabilityFlag16, cleared once needCapA6 exceeds 49.
  // Mac oracle candidate GetNumShipsToBuild (the class's only other ()->count
  // virtual besides GetNumCarsToBuild, whose tradeCapacity gate pins it to 0x17).
  virtual short GetNumShipsToBuild(); // 0x16 0x4be480
  // Count of transport (rail) cars to build this pass (FillOrders' first loop
  // bound): clamps/returns capabilityFlag14, cleared once tradeCapacity exceeds 49.
  // Mac oracle: GetNumCarsToBuild.
  virtual short GetNumCarsToBuild(); // 0x17 0x4be4c0
  // Per-car build step run once per GetNumCarsToBuild: no-op while
  // GetDiplomacyCounterA2() is nonzero, otherwise TryDecayRelationNeedScores9And8().
  // Mac oracle candidate DoIncreasedTransport (hedged: the owner-side callee's
  // semantics are still provisional).
  virtual bool DoIncreasedTransport(); // 0x18 0x4be650
  // Behaviour-derived name (no confident Mac match): notifies the owner nation of
  // round-robin need slot field10 (TGreatPower slot 0x48,
  // TryIncrementNationResourceNeedTargetTowardCurrent), then advances field10
  // through 0..4.
  virtual void AdvanceNeedTargetRoundRobin(); // 0x19 0x4be690
  // Base body is a bare RET 0x4 no-op; the TCityInteriorMinister override latches
  // pendingShipType32 = (orderKind == 2) + 1. Mac oracle: PleaseBuildShip(short).
  virtual void PleaseBuildShip(short orderKind);    // 0x1a 0x4be3f0
  virtual void IndustryOrder(short industrySlot);   // 0x1b 0x4be410
  virtual void PleaseBuildLandUnit(short unitType); // 0x1c 0x4be430, Mac oracle
  // 0x1d/0x1e/0x1f: Mac oracle Get/Get/ResetHistoricalNeedFor(long) family. The
  // TCityInteriorMinister overrides pin the mapping: 0x1e reads and 0x1f clears the
  // same short[23] table (historical need), 0x1d reads the parallel table
  // (exterior need). Base bodies just return the argument / no-op.
  virtual short GetExteriorNeedFor(int orderType);    // 0x1d 0x4be150
  virtual short GetHistoricalNeedFor(int orderType);  // 0x1e 0x4be170
  virtual void ResetHistoricalNeedFor(int orderType); // 0x1f 0x4be190

  // Own fields at +0x10..+0x28 (RTTI m_nObjectSize proves this block is
  // TInteriorMinister-only, distinct from TForeignMinister's own +0x10..+0x48 block --
  // see TMinister.h). capabilityFlag14/16 at +0x14/+0x16 coincide in offset (not
  // identity) with TForeignMinister's fields of the same name; every
  // TCityInteriorMinister-family constructor (TSteelCityMinister, ...) sets both to 1.
  short field10;          // +0x10 — set from SetParameters' second argument
  short field12;          // +0x12 — set from SetParameters' first argument
  short capabilityFlag14; // +0x14
  short capabilityFlag16; // +0x16
  // +0x18..0x25 — 7-entry short table, byte-swapped per-pair on ReadFrom (0x4be290);
  // semantic contents not yet recovered.
  short trailingTable[7];
  // +0x26..+0x28: zero field-xrefs; genuinely untouched, not an unrecovered field.
  unsigned char unused26[0x28 - 0x26];
};
ASSERT_SIZE(TInteriorMinister, 0x28);
