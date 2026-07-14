#pragma once

#include "game/TMinister.h"

class TGreatPower;
class TStream;

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters();

  DECLARE_DYNCREATE(TForeignMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short DispatchNationStateEventCode10(short nationSlot) override;
  // slot 0x12 (body 0x0052f4b0) — seed the foreign-minister state bytes (0x49-0x4f)
  // and capability flags; sets flag 0x14 when the owner's treasury is negative.
  virtual void InitializeForeignMinisterStateFlags();
  // slot 0x13 (0x0052f4f0) — counters1e[index] += delta.
  virtual void AddToForeignMinisterCounterAtIndex(short index, short delta);
  // slot 0x14 (0x0052f520) — set capability flag 0x14.
  virtual void SetForeignMinisterReadyFlag14();
  // slot 0x15 (0x0052f540) — store primary/secondary targets at 0x10/0x12.
  virtual void SetForeignMinisterPrimaryAndSecondaryTargets(short primary, short secondary);

  // slot 0x16 (0x0052fd10) — refresh minister sub-state gated on the sim-mode getter.
  virtual void RefreshForeignMinisterStateByLocalizationMode();
  virtual void MinisterSlot17();
  virtual void MinisterSlot18();
  virtual void MinisterSlot19();
  virtual void MinisterSlot1A(short arg = 0);
  virtual void MinisterSlot1B();
  // slot 0x1c (body 0x005308b0) — difficulty-indexed army/navy score-threshold predicate.
  virtual char EvaluateLocalizedScoreThresholdPredicateForNationValue(int nationCode);
  // slot 0x1d (body 0x00530b30) — mark the first eligible nation as an action
  // candidate, but only while no candidate is active yet.
  virtual void DispatchAction210ToFirstEligibleNationIfIdle();
  virtual void MinisterSlot1E();
  virtual void MinisterSlot1F(short queueIndex); // byte 0x7c: processes a queued proposal row
  virtual void Call80();
  virtual void MinisterSlot21();
  virtual char MinisterSlot22();
  virtual void Call8C();
  virtual void Call90();
  virtual void Call94();
  virtual void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation);
  virtual void RecomputeOrderStateSlot9C();

  unsigned char field48;    // +0x48 — cleared by the constructor
  unsigned char flags49[7]; // +0x49..0x4f — seeded to 1 by InitializeForeignMinisterStateFlags
  unsigned char foreignState50[0x80 - 0x50]; // +0x50..0x7f — remaining unrecovered state
};
