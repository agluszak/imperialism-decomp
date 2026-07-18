#pragma once

#include "game/TGreatPower.h"

// VTABLE: IMPERIALISM 0x00654088
class TAutoGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TAutoGreatPower)
  // `missionQueue` (the whole 0x964+ tail block is TAutoGreatPower-only data that is
  // still declared on TGreatPower; see worklog 2026-06-10).

  TAutoGreatPower();
  ~TAutoGreatPower() override;
  // Destructor real body 0x004e6bb0; scalar deleting destructor 0x004e6b80
  // (both paired via symbols.csv names).

  // Overrides of TGreatPower virtuals:
  // slots 0x05/0x06 — 0x004e73f0/0x004e72c0: AI tail-state stream I/O.
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  // slot 0x07 — 0x004e7230: drain missionQueue then run the base Free().
  void Free() override;
  // slot 0x14 — 0x004ea150: join-empire reset plus clearing map-action caches.
  void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) override;
  // slot 0x19 — 0x004ea290: add region and queue a map-action mission.
  void AddRegionIdToNationOwnedRegionList(int regionId) override;
  // slot 0x20 — 0x004e7630: resource delta with need clamp before base totals.
  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  // slot 0x23 — 0x004e7b50: proposal queue with alliance guards.
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) override;
  // slot 0x25 — 0x004e7c50: policy side effects before slot 0x94 dispatch.
  void NotifyActionSlot94(int sourceNation, int actionCode) override;
  // slot 0x4d — 0x004ea470: rebuild yields and roll field 0x134 into 0x136.
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void) override;
  // slots 0x56/0x57 — 0x004e78d0/0x004e78f0: minister callbacks when city exists.
  void RunSlot4CThenSortTrackedOrders(void) override;
  void ResetField900FromNeedCapA6(void) override;
  // slot 0x5a — 0x004e7810: recompute aid budget and clear need matrix.
  void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) override;
  // slot 0x61 — 0x004e7990: foreign-minister slots 0x90/0x94.
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) override;
  // slot 0x74 — 0x004e7b20: forward to base policy apply with cost checks.
  bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                        short policyCode) override;
  // slot 0x81 — 0x004e7be0: replay proposal rows then reset policy state.
  void ProcessPendingDiplomacyProposalQueue(void) override;
  // slot 0xa1 — 0x004e9ed0: war-transition propagation from advisory action.
  void ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot, int policyCode,
                                                            int sourceNationSlot) override;
  // slot 0xa2 — 0x004e9a50: select and queue advisory map missions (case 16).
  void SelectAndQueueAdvisoryMapMissionsCase16(void) override;
  // slot 0xa4 — 0x004eb0d0: prune invalid missionQueue entries.
  void PruneInvalidTrackedEntriesAndNotifyOwner(void) override;
  // slots 0xad/0xae — 0x004eaa20/0x004eae70: AI turn tail hooks.
  void NoOpTailStateHookSlot2B4(void) override;
  void NoOpTailStateHookSlot2B8(int arg) override;
  // slot 0x36 — 0x004e7550: forward to slots 0x4d/0x4e when city exists.
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) override;
  // slot 0x67 — 0x004e7680: need assignment with capability caps / escalation roll.
  void AssignNeedSlotFromSourceSlot19C(short needSlot, short sourceNation) override;
  // slot 0x9f — 0x004e7cc0: war-transition propagation across eligible allied nations.
  int CheckTransitionSlot27C(int targetNation, int sourceNation) override;
  // slot 0xab — 0x004e7510: 'lost' game-state event when redraw is enabled.
  void DispatchTurnEvent11F8NoPayloadSlot2AC(void) override;
  // slot 0x18 — 0x004ea1c0: also drop the matching mission and map-node flag.
  void RemoveRegionIdFromNationOwnedRegionList(int regionId) override;
  // slot 0x22 — 0x004e79d0: forward to the foreign minister or queue a tracked entry.
  char TryDispatchNationActionViaUiContextOrFallback(int targetNation, int arg2, int arg3,
                                                     int slotIndex) override;
  // slot 0x38 — 0x004e7590: interior-minister slot 0x54 when city exists.
  void OrphanRetStub_004dcc30(void) override;
  // slot 0x71 — 0x004e7a50: flush actionMetricByQuarter into city stock.
  void ClearDiplomacyState1c6Block(void) override;
  // slot 0x72 — 0x004e7af0: foreign-minister slot 0x58 when city exists.
  void BeginTurnDiplomacyPrePassSlot1c8() override;
  // slot 0x83 — 0x004e9f10: prune candidateNationFlags; true while any stays active.
  char HasActiveCandidateNationSlots(void) override;
  // slot 0x84 — 0x004e9ff0: mark a candidate nation (and its port zone) active.
  void SetCandidateNationFlagAndPortZoneState(int targetNation) override;
  // slot 0x85 — 0x004ea0e0: clear a candidate nation (and its port zone).
  void NotifyAllianceSlot214(int targetNation) override;
  // slot 0xa0 — 0x004e7ec0: war-transition propagation for a nation pair.
  int PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) override;
  // slot 0xaf — 0x004e6b10: pressure update stubbed out for AI nations.
  char UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  // slot 0x9d — 0x004e8040: alliance-aware strength evaluation against the strongest
  // peer; true when minister skill (slot 0x8a) clears the combined score.
  char ReturnZeroSlot9D(int targetNation) override;
  // slot 0xa7 — 0x004ea300: base reset plus marking every owned region / the port
  // zone of targetNation as action candidates.
  void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) override;
  // slots 0xb0/0xb1 — 0x004ea430/0x004ea450: no-op overrides for AI nations.
  void DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) override;
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void) override;

  // Quarterly / nation-state event stubs the AI nation leaves empty.
  // slots 0x3c/0x3d/0x3e — 0x004e7910/0x004e7930/0x004e7950.
  void DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) override;
  // slot 0x6a — 0x004e7970: AI leaves the base 1c6→250 snapshot empty.
  void SnapshotDiplomacyState1c6Into250(void) override;
  // slot 0x80 — 0x004e7ca0.
  void DispatchTurnEvent2103WithNationFromRecord() override;
  // slots 0x2c8/0x2cc — base vtable NULL; TAutoGreatPower fills these entries.
  // slot 0xb2 — 0x004e75c0.
  virtual undefined OrphanCallChain_C4_I28_004e75c0(int needSlot);
  // slot 0xb3 — 0x004ea990.
  virtual undefined IterateLinkedListCursorAndRelinkNodeOwners_004ea990();
};
