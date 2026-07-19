#pragma once

#include "game/TMinister.h"

class TGreatPower;
class TStream;

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters(TGreatPower* owner);

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
  // slot 0x1a (0x0052fdc0) — set per-nation interaction enable flags from a terrain
  // class-200 scan and relation-standing threshold. void (ret 0); Call90 pushes an
  // ignored short at its call site.
  virtual void UpdateNationInteractionEnableFlagsByTerrainAndRelation();
  virtual void MinisterSlot1B();
  // slot 0x1c (body 0x005308b0) — difficulty-indexed army/navy score-threshold predicate.
  virtual char EvaluateLocalizedScoreThresholdPredicateForNationValue(int nationCode);
  // slot 0x1d (body 0x00530b30) — mark the first eligible nation as an action
  // candidate, but only while no candidate is active yet.
  virtual void DispatchAction210ToFirstEligibleNationIfIdle();
  // slot 0x1e (0x00530200) — 1359-byte SEH turn-event-hint queuer; unported stub.
  virtual void QueueTurnEventHintActionsByNationMetricsAndCompatibility();
  // slot 0x1f (0x00530fa0) — validate a queued proposal row and dispatch accept/queue.
  virtual void ValidateProposalSelectionAndQueueEvent1C(short queueIndex);
  virtual void Call80();
  virtual void MinisterSlot21();
  // slot 0x22 (0x0052f730) — true if any diplomacy option (0xd/0xe/0xf) meets the
  // owner's trade-capacity threshold.
  virtual int HasAnyOptionDToFMeetingNationThreshold();
  virtual void Call8C();
  virtual void Call90();
  virtual void Call94();
  virtual void DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation);
  virtual void RecomputeOrderStateSlot9C();

  // Own fields at +0x10..+0x48 (moved from TMinister -- RTTI m_nObjectSize proves this
  // block is TForeignMinister-only, not shared base state; see TMinister.h).
  short field10;          // +0x10 — primary target (SetForeignMinisterPrimaryAndSecondaryTargets)
  short field12;          // +0x12 — secondary target
  short capabilityFlag14; // +0x14
  short capabilityFlag16; // +0x16
  unsigned char pad18[0x1a - 0x18]; // +0x18..0x19 — still unrecovered
  short field1a;                    // +0x1a — ctor seeds 5 (0x52f070)
  short field1c;                    // +0x1c — ctor seeds 2 (0x52f070)
  short counters1e[3]; // +0x1e..0x23 — per-index counter array (AddToForeignMinisterCounterAtIndex)
  short capabilityFlag24;
  short capabilityFlag26;
  short capabilityFlag28;
  unsigned char pad2a[0x48 - 0x2A];

  unsigned char field48;    // +0x48 — cleared by the constructor
  unsigned char flags49[7]; // +0x49..0x4f — seeded to 1 by InitializeForeignMinisterStateFlags
  unsigned char foreignState50[0x80 - 0x50]; // +0x50..0x7f — remaining unrecovered state
};
