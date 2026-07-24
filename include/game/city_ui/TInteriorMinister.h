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
  // Walks g_aInteriorMinisterNeedPriorityOrder_00696408 (10 need types, priority order)
  // and raises each one's target toward its current value via owner slot 0x45, clamping
  // every top-up to the nation's remaining headroom (needCapA6 - needsOverCapFlag) and
  // returning early the moment that headroom reaches zero. 0x4be520, __thiscall, no args.
  virtual void TopUpNeedTargetsByPriorityWithinCap();
  // The per-turn economic-AI pass. Runs TryDecayRelationNeedsUnlessDiplomacyPending()
  // once per GetTradeCapacityActionAllowance() (re-read each iteration, so clearing the
  // allowance ends the loop); then, once the owner's
  // IsNationResourceNeedCurrentSumExceedingCapA6() is true, decays relation-need scores
  // via the owner's TryDecayRelationNeedScores9AndB() once per
  // GetResourceNeedActionAllowance(), accumulating the results; finally calls
  // AdvanceRoundRobinResourceNeedTarget() that many times, servicing one resource's need
  // target per call. 0x4be5b0, __thiscall, no args.
  virtual void FillOrders();
  // Slots 0x16-0x1f: TInteriorMinister's own new virtuals (real vtable 0x650808 is
  // 32 slots, 0x00-0x1f). TCityInteriorMinister inherits 0x16-0x19 and overrides
  // 0x1a-0x1f.
  //
  // 0x16/0x17 are the two per-turn action allowances FillOrders uses as loop counts.
  // Each returns a 0/1 capability flag that both constructors seed to 1 and that is
  // permanently cleared once the owning nation outgrows the corresponding capacity
  // (the threshold is 49 in both, compared as `> 0x31`).

  // Returns capabilityFlag16, first clearing it once owner->needCapA6 exceeds 49. A null
  // owner reads as need 0, so the flag survives. Gates the relation-need decay loop.
  virtual short GetResourceNeedActionAllowance(); // 0x16 0x4be480
  // Returns capabilityFlag14, first clearing it once owner->tradeCapacity exceeds 49.
  // Gates the TryDecayRelationNeedsUnlessDiplomacyPending loop.
  virtual short GetTradeCapacityActionAllowance(); // 0x17 0x4be4c0
  // Returns false outright while the owner has diplomacy pending
  // (GetDiplomacyCounterA2() != 0, owner slot 0x1d); otherwise returns the owner's
  // TryDecayRelationNeedScores9And8() result (owner slot 0x4b).
  virtual bool TryDecayRelationNeedsUnlessDiplomacyPending(); // 0x18 0x4be650
  // Nudges one resource's need target toward its current value via the owner's
  // TryIncrementNationResourceNeedTargetTowardCurrent(field10) (owner slot 0x48), then
  // advances field10 round-robin through 0..4 -- one resource serviced per call.
  virtual void AdvanceRoundRobinResourceNeedTarget(); // 0x19 0x4be690
  // Queues a ship for the given advisory order kind: latches pendingShipType32 to 2 for
  // order kind 2 and 1 otherwise, and only while it is still unset. Base body is a bare
  // RET 0x4 no-op (a nation with no city minister has nowhere to queue it).
  virtual void LatchPendingShipTypeForOrderKind(short orderKind); // 0x1a 0x4be3f0
  virtual void IndustryOrder(short industrySlot);                 // 0x1b 0x4be410
  virtual void PleaseBuildLandUnit(short unitType);               // 0x1c 0x4be430, Mac oracle
  // 0x1d-0x1f are the per-order-type accessors over TCityInteriorMinister's two parallel
  // short[23] tables. The base bodies are degenerate (identity/no-op) because a minister
  // without those tables has no per-type history: 0x1d and 0x1e return the order type
  // they were handed and 0x1f does nothing.

  // Accumulated unmet need per order type (orderTypeTable12A); feeds the resource
  // weighting in the city order planner.
  virtual short GetAccumulatedResourceNeed(int orderType); // 0x1d 0x4be150 — base returns arg
  // Accumulated demand pressure per order type (orderTypeTable158). TAutoGreatPower
  // starts a foreign acquisition effort for an order type once this reaches 5.
  virtual short GetUnmetDemandPressure(int orderType); // 0x1e 0x4be170 — base returns arg
  // Resets that pressure for one order type; TAutoGreatPower purges all four advisory
  // order types this way when the nation goes to war.
  virtual void ClearUnmetDemandPressure(int orderType); // 0x1f 0x4be190 — base no-op

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
