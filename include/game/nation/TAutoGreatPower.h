#pragma once

#include "compat.h"

#include "game/nation/TGreatPower.h"
#include "game/ui_tags_common.h"

// VTABLE: IMPERIALISM 0x00654088
class TAutoGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TAutoGreatPower)

  TAutoGreatPower();
  ~TAutoGreatPower() override;
  // MacApp two-phase initializer. Mac oracle: TAutoGreatPower::IAutoGreatPower(short,
  // short, short, short, short) -- name taken from there (Hard Rule 12), but NOT the
  // parameter types: the retail body reads arg1 and arg2 as dwords (0x4e6c2e/0x4e6c3e)
  // and only arg5 through MOVSX word (0x4e6c4b), so the leading pair is int-width here.
  // The Windows listing outranks the Mac signature on types.
  void IAutoGreatPower(int nationSlot, int nationInitializationMode, short cityMinisterPolicyId,
                       short foreignMinisterPolicyId, short defenseMinisterPolicyId);
  // Destructor real body 0x004e6bb0; scalar deleting destructor 0x004e6b80
  // (both paired via symbols.csv names).

  // Overrides of TGreatPower virtuals:
  // slots 0x05/0x06 — 0x004e73f0/0x004e72c0: AI tail-state stream I/O.
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  // slot 0x07 — 0x004e7230: drain missionQueue then run the base Free().
  void Free() override;
  // slot 0x14 — 0x004ea150: join-empire reset plus clearing map-action caches.
  void BecomeProtectorateOf(int targetNationSlot) override;
  // slot 0x19 — 0x004ea290: add region and queue a map-action mission.
  void AddProvince(int regionId) override;
  // slot 0x20 — 0x004e7630: accumulate negative resource 7..12 deltas before base totals.
  void PurchaseItem(short resourceKind, short amount, short price) override;
  // slot 0x23 — 0x004e7b50: proposal queue with alliance guards.
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  // slot 0x25 — 0x004e7c50: policy side effects before slot 0x94 dispatch.
  void AddNoticeFrom(short sourceNation, short actionCode) override;
  // slot 0x4d — 0x004ea470: rebuild yields and roll field 0x134 into 0x136.
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void) override;
  // slots 0x56/0x57 — 0x004e78d0/0x004e78f0: minister callbacks when city exists.
  void MoveCivilians(void) override;
  void MoveArmy(void) override;
  // slot 0x5a — 0x004e7810: recompute aid budget and clear need matrix.
  void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) override;
  // slot 0x61 — 0x004e7990: foreign-minister slots 0x90/0x94.
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) override;
  // slot 0x74 — 0x004e7b20: forward to base policy apply with cost checks.
  bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                        short policyCode) override;
  // slot 0x81 — 0x004e7be0: replay proposal rows then reset policy state.
  void ReplyToDiplomacyOffers(void) override;
  // slot 0xa1 — 0x004e9ed0: war-transition propagation from advisory action.
  void QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot, int transitionMode,
                                                     int sourceNationSlot) override;
  // slot 0xa2 — 0x004e9a50: select and queue advisory map missions (case 16).
  void SelectAndQueueAdvisoryMapMissionsCase16(void) override;
  // slot 0xa4 — 0x004eb0d0: prune invalid missionQueue entries.
  void PruneInvalidTrackedEntriesAndNotifyOwner(void) override;
  // slots 0xad/0xae — 0x004eaa20/0x004eae70: AI turn tail hooks.
  void RecomputeAiExpansionAndMissionPressureScores(void) override;
  void RefreshTrackedEntriesAndReplanAiDevelopment(int unused) override;
  // slot 0x36 — 0x004e7550: forward to slots 0x4d/0x4e when city exists.
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) override;
  // slot 0x67 — 0x004e7680: need assignment with capability caps / escalation roll.
  void SetTradeOffersFor(short resourceKind, short offerContext) override;
  // slot 0x9f — 0x004e7cc0: war-transition propagation across eligible allied nations.
  int HandleWarTransitionRequest(int targetNation, int sourceNation) override;
  // slot 0xab — 0x004e7510: 'lost' game-state event when redraw is enabled.
  void SorryYouLose(void) override;
  // slot 0x18 — 0x004ea1c0: also drop the matching mission and map-node flag.
  void LoseProvince(int regionId) override;
  // slot 0x22 — 0x004e79d0: forward to the foreign minister or queue a tracked entry.
  char ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  // slot 0x38 — 0x004e7590: interior-minister slot 0x54 when city exists.
  void FillInteriorMinisterOrders(void) override;
  // slot 0x71 — 0x004e7a50: flush actionMetricByQuarter into city stock.
  void ClearTradeOffers(void) override;
  // slot 0x72 — 0x004e7af0: foreign-minister slot 0x58 when city exists.
  void SetDiplomacyPolicies() override;
  // slot 0x83 — 0x004e9f10: prune candidateNationFlags; true while any stays active.
  char HasActiveCandidateNationSlots(void) override;
  // slot 0x84 — 0x004e9ff0: mark a candidate nation (and its port zone) active.
  void SetEnemy(int targetNation) override;
  // slot 0x85 — 0x004ea0e0: clear a candidate nation (and its port zone).
  void StopBeingEnemiesWith(int targetNation) override;
  // slot 0xa0 — 0x004e7ec0: war-transition propagation for a nation pair.
  int HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                             char swapRoles) override;
  // slot 0xaf — 0x004e6b10: intentional AI override. TGreatPower owns the live
  // pressure/escalation routine at 0x004db380; automated nations suppress it.
  char UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  // slot 0x9d — 0x004e8040: alliance-aware strength evaluation against the strongest
  // peer; true when minister skill (slot 0x8a) clears the combined score.
  char PassesDiplomacyStrengthThresholdForTarget(int targetNation) override;
  // slot 0xa7 — 0x004ea300: base reset plus marking every owned region / the port
  // zone of targetNation as action candidates.
  void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) override;
  // slots 0xb0/0xb1 — 0x004ea430/0x004ea450: no-op overrides for AI nations.
  void AnnounceLater(short orderKind, short payload, short flags) override;
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void) override;

  // Quarterly / nation-state event stubs the AI nation leaves empty.
  // slots 0x3c/0x3d/0x3e — 0x004e7910/0x004e7930/0x004e7950.
  void DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) override;
  // slot 0x6a — 0x004e7970: AI leaves the base 1c6→250 snapshot empty.
  void RememberTradeBids(void) override;
  // slot 0x80 — 0x004e7ca0.
  void DispatchTurnEvent2103WithNationFromRecord() override;
  // slots 0x2c8/0x2cc — base vtable NULL; TAutoGreatPower fills these entries.
  // slot 0xb2 — 0x004e75c0: raise the three AI planning metrics for needSlot.
  virtual void RaiseNeedPlanningMetrics(int needSlot);
  // slot 0xb3 — 0x004ea990: free every queued mission.
  virtual void KillMissions();

  // 0x4eb8b0 — repeatedly assigns the highest-priority tracked mission's action to a
  // matching order/unit. Resets every missionQueue entry (SmokeEmIfYouGotEm), then loops:
  // (1) pick the best-scoring TNavyMission (GetNavyMission identity filter — army
  // entries return null there); if found, build its 9-category weight profile
  // (AccumulateLack) and pair it with the best same-nation, unassigned
  // (field2c == nullptr) TShip primary-order node (FitnessOf), dispatching
  // via AcceptReenforcement and restarting. (2) Otherwise pick the best-scoring TArmyMission
  // (GetArmyMission identity filter, with a state08/marker11 tie-break against a
  // runner-up candidate), build its weight profile, and pair it with the best unassigned
  // (ownerMission40 == nullptr) militaryUnitList44 unit (FitnessOf),
  // dispatching via AdoptUnitSlot80 and restarting. Stops when neither pass finds a
  // candidate to act on.
  void AssignTrackedEntryActionsByProfileToOrdersOrUnits(int unused);

  // Sorts the mission queue, then marks entries whose class requirements cannot be
  // satisfied by the remaining class mask or whose value/cost ratio loses to the next
  // entry of the same class. 0x4eb6b0.
  void UpdateTrackedEntryEligibilityByClassMaskAndRatio(int unused);

  // Chooses and applies city/industry development actions while resource pools remain.
  void PlanAiDevelopmentActionsFromResourcePools(int unused);
  float ComputeAiIndustryActionCostFromSlot(short industrySlot);
  float ComputeAiCityActionCostFromSlotAndMode(short actionSlot, char skipContextBias);
  float GetCachedAiCityActionContextBias(short selector);

  void CreateMission(eMissionType missionType, int mapNodeIndex, TZone* zoneContext,
                     int relatedMapNodeIndex);
  void RemoveMission(eMissionType missionType, int key, TZone* zoneContext);
  void MReassess();
  // For every unassigned (ownerMission40 == nullptr) militia-category unit in
  // militaryUnitList44, finds the queued mission (kind 3, keyed by the
  // unit's own tileIndex06) in missionQueue and adopts the unit into it. 0x4eafa0.
  void SeedTrackedEntryAssignmentsFromEligibleUnits();
  void QueueMapActionMissionsForPortZoneCandidates();
  // Case-16 advisory pass: resets transient candidate flags, re-marks candidate regions
  // from flagged nations'/minors' owned-region lists, and (when not at war) scores and
  // flags the top provinces per advisory order type {2,3,4,6}. 0x4e92b0, __thiscall.
  void PopulateCase16AdvisoryMapNodeCandidateState();
  // Writes `value` into portZoneStateFlags[contextOrdinal] (`contextOrdinal` is a
  // TZone::GetContextOrdinalOrInvalid() result). Called from
  // TControlSeaZoneMission::GetReplacementSlot48's terrain-coverage-not-found path
  // (0x5389a9) to clear this nation's flag for the target port zone's context ordinal.
  void SetByteFlagAtOffsetAF0ByIndex(int contextOrdinal, char value); // 0x4e8bf0
  // Mac oracle: SetEnemy. Marks (or clears) the given nation's first port-zone context
  // in portZoneStateFlags. Only nations that actually hold regions are considered, and
  // a minor nation (encoded slot 100..199) is never marked as an enemy -- only cleared.
  // 0x004e8300, __thiscall.
  void SetEnemy(int nationSlot, char makeEnemy);
  // Sets mapNodeStateFlags[provinceIndex] to `value`, except when value == 1 and the
  // province's map-action-context link is unavailable (no active context for this
  // nation), in which case it's forced to 0 instead. Same gate/array
  // QueueMapActionMissionsForPortZoneCandidates already uses directly. 0x4e8b50.
  void SetMapStateByteFlag970WithRuntimeGate(int provinceIndex, int value);

  // Tail AI-state block: moved here from TGreatPower (RTTI m_nObjectSize proves this
  // data is TAutoGreatPower-only -- see the comment at the end of TGreatPower's field
  // list). Object ends at 0x964 (base TGreatPower) + this block; original object size
  // is 0xb70 (CRuntimeClass m_nObjectSize), so the trailing 4 bytes below are still not
  // semantically recovered.
  short actionMetricByQuarter[6];
  unsigned char mapNodeStateFlags[0x180];
  unsigned char portZoneStateFlags[0x70];
  TSortedList* missionQueue;
  float expansionPressurePerCompatibleRegionB64;
  float averageUnitDivergencePerOwnedRegionB68;
  float activeMissionPressureAverageB6c;
};
ASSERT_SIZE(TAutoGreatPower, 0xb70);

bool SelectBestCityDevelopmentFromResourcePools(int nationSlot, int* resourcePools,
                                                TMilitaryUnit** bestUnitByType,
                                                char* selectedIsIndustry, char* selectedIsUpgrade,
                                                int* selectedSlot, int unused,
                                                float* selectedWeightedCost);

// Scores the current AI nation's owned regions as city-development targets and returns the
// best region id, or -1 when the nation is unavailable/ineligible. 0x00540440, __cdecl.
int ComputeBestNationTileDevelopmentScore(NationSlot nationSlot);
