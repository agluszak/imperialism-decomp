#pragma once

#include "game/TGreatPower.h"

// VTABLE: IMPERIALISM 0x00654088
class TAutoGreatPower : public TGreatPower {
public:
  // The auto-tracked list lives at +0xb60 — that is the base header's tail field
  // `missionQueue` (the whole 0x964+ tail block is TAutoGreatPower-only data that is
  // still declared on TGreatPower; see worklog 2026-06-10).

  TAutoGreatPower();
  // Destructor is compiler-generated: real dtor body 0x004e6bb0, scalar deleting
  // destructor 0x004e6b80 (both paired via symbols.csv names).

  // Overrides of TGreatPower virtuals:
  // slot 0x07 — 0x004e7230: drain autoTrackedListB60 then run the base release.
  void ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void);
  // slot 0x36 — 0x004e7550: forward to slots 0x4d/0x4e when a relation manager exists.
  void VTableIndex54_Provisional(void);
  // slot 0x67 — 0x004e7680: need assignment with capability caps / escalation roll.
  void AssignNeedSlotFromSourceSlot19C(int needSlot, int sourceNation);
  // slot 0x9f — 0x004e7cc0: war-transition propagation across eligible allied nations.
  int CheckTransitionSlot27C(int targetNation, int sourceNation);
  // slot 0xab — 0x004e7510: 'lost' game-state event when redraw is enabled.
  void DispatchTurnEvent11F8NoPayloadSlot2AC(void);

  static void* GetTAutoGreatPowerClassNamePointer(void);
  void* ConstructTAutoGreatPowerBaseState(void);
  void RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix(void);
  void ReplayQueuedDiplomacyProposalRowsAndProcessQueue(void);
};
