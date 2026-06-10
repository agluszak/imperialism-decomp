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
  // slot 0x18 — 0x004ea1c0: also drop the matching mission and map-node flag.
  void RemoveRegionIdAndRunTrackedObjectCleanup(int regionId);
  // slot 0x22 — 0x004e79d0: forward to the foreign minister or queue a tracked entry.
  char DispatchOrQueueDiplomacyRequestSlot88_Provisional(int targetNation, int arg2, int arg3,
                                                         int slotIndex);
  // slot 0x38 — 0x004e7590: interior-minister slot 0x54 when a relation manager exists.
  void VTableIndex56_Provisional(void);
  // slot 0x71 — 0x004e7a50: flush actionMetricByQuarter into relation-manager fieldB6.
  void ClearDiplomacyState1c6Block(void);
  // slot 0x72 — 0x004e7af0: foreign-minister slot 0x58 when a relation manager exists.
  void BeginTurnDiplomacyPrePassSlot1c8();
  // slot 0x83 — 0x004e9f10: prune candidateNationFlags; true while any stays active.
  char VTableSlot20C_Provisional(void);
  // slot 0x84 — 0x004e9ff0: mark a candidate nation (and its port zone) active.
  void VTableSlot84_Provisional(int targetNation);
  // slot 0x85 — 0x004ea0e0: clear a candidate nation (and its port zone).
  void NotifyAllianceSlot214(int targetNation);
  // slot 0xa0 — 0x004e7ec0: war-transition propagation for a nation pair.
  int PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode);
  // slot 0xaf — 0x004e6b10: pressure update stubbed out for AI nations.
  void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  // slot 0x9d — 0x004e8040: alliance-aware strength evaluation against the strongest
  // peer; true when minister skill (slot 0x8a) clears the combined score.
  char ReturnZeroSlot9D(int targetNation);
  // slot 0xa7 — 0x004ea300: base reset plus marking every owned region / the port
  // zone of targetNation as action candidates.
  void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation);
  // slots 0xb0/0xb1 — 0x004ea430/0x004ea450: no-op overrides for AI nations.
  void DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags);
  void VTableIndex177_Provisional(void);

  static void* GetTAutoGreatPowerClassNamePointer(void);
  void* ConstructTAutoGreatPowerBaseState(void);
  void RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix(void);
  void ReplayQueuedDiplomacyProposalRowsAndProcessQueue(void);
};
