#pragma once

#include "game/TMinister.h"

// AI interior minister branch.
// VTABLE: IMPERIALISM 0x00650808
class TInteriorMinister : public TMinister {
public:
  TInteriorMinister();

  DECLARE_DYNCREATE(TInteriorMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short GetRankingCriterionForGP(short nationSlot) override;
  void MakeNewCity(TCity* city) override;
  // Two stack args (RET 0x8; Ghidra reads two shorts). slot 0x12 0x4be450
  virtual void MinisterSlot12(short arg1, short arg2);
  // Zeroes trailingTable (+0x18..0x25, 7 shorts). 0x4be4f0, __thiscall, no args.
  virtual void Call4C();
  virtual void MinisterSlot14();
  // Runs InteriorSlot18() once per InteriorSlot17() (re-read each iteration); then,
  // once the owner's IsNationResourceNeedCurrentSumExceedingCapA6() is true, decays
  // relation-need scores via the owner's TryDecayRelationNeedScores9AndB() once per
  // InteriorSlot16(), accumulating the results; finally runs InteriorSlot19() that
  // many times. 0x4be5b0, __thiscall, no args.
  virtual void FillOrders();
  // Slots 0x16-0x1f: TInteriorMinister's own new virtuals (real vtable 0x650808 is
  // 32 slots, 0x00-0x1f). TCityInteriorMinister inherits 0x16-0x19 and overrides
  // 0x1a-0x1f.
  // Clamps/returns capabilityFlag16: clears it once needCapA6 exceeds 49.
  virtual short InteriorSlot16(); // 0x16 0x4be480
  // Clamps/returns capabilityFlag14: clears it once tradeCapacity exceeds 49.
  virtual short InteriorSlot17(); // 0x17 0x4be4c0
  // True unless GetDiplomacyCounterA2() is nonzero, in which case it falls back to
  // TryDecayRelationNeedScores9And8().
  virtual bool InteriorSlot18(); // 0x18 0x4be650
  // Notifies the owner nation of round-robin slot field10 (TGreatPower slot 0x48),
  // then advances field10 through 0..4.
  virtual void InteriorSlot19(); // 0x19 0x4be690
  // One stack arg each (base bodies are bare RET 0x4 no-ops; the
  // TCityInteriorMinister overrides read it as a short).
  virtual void InteriorSlot1A(short arg);         // 0x1a 0x4be3f0
  virtual void IndustryOrder(short industrySlot); // 0x1b 0x4be410
  virtual void InteriorSlot1C(short arg);         // 0x1c 0x4be430
  virtual short InteriorSlot1D(int arg);          // 0x1d 0x4be150 — returns arg
  virtual short InteriorSlot1E(int arg);          // 0x1e 0x4be170 — returns arg
  virtual void InteriorSlot1F(int arg);           // 0x1f 0x4be190 — no-op

  // Own fields at +0x10..+0x28 (RTTI m_nObjectSize proves this block is
  // TInteriorMinister-only, distinct from TForeignMinister's own +0x10..+0x48 block --
  // see TMinister.h). capabilityFlag14/16 at +0x14/+0x16 coincide in offset (not
  // identity) with TForeignMinister's fields of the same name; every
  // TCityInteriorMinister-family constructor (TSteelCityMinister, ...) sets both to 1.
  short field10;          // +0x10 — set from MinisterSlot12's arg2 (0x4be450)
  short field12;          // +0x12 — set from MinisterSlot12's arg1
  short capabilityFlag14; // +0x14
  short capabilityFlag16; // +0x16
  // +0x18..0x25 — 7-entry short table, byte-swapped per-pair on ReadFrom (0x4be290);
  // semantic contents not yet recovered.
  short trailingTable[7];
  unsigned char pad26[0x28 - 0x26];
};
