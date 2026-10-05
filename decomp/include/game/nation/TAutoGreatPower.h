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
  void IAutoGreatPower(int nationSlot, int nationInitializationMode, short cityMinisterPolicyId,
                       short foreignMinisterPolicyId, short defenseMinisterPolicyId);
  // Destructor real body 0x004e6bb0; scalar deleting destructor 0x004e6b80
  // (both paired via symbols.csv names).

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
  void InitializeTradeStatus(void) override;
  // slot 0x61 — 0x004e7990: foreign-minister slots 0x90/0x94.
  void SetTradeBids(void) override;
  // slot 0x74 — 0x004e7b20: forward to base policy apply with cost checks.
  bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                        short policyCode) override;
  // slot 0x81 — 0x004e7be0: replay proposal rows then reset policy state.
  void ReplyToDiplomacyOffers(void) override;
  // slot 0xa1 — 0x004e9ed0: war-transition propagation from advisory action.
  void QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot, int transitionMode,
                                                     int sourceNationSlot) override;
  // slot 0xa2 — 0x004e9a50: select and queue advisory map missions (case 16).
  void SelectAndQueueAdvisoryMapMissions(void) override;
  // slot 0xa4 — 0x004eb0d0: prune invalid missionQueue entries.
  void ReplaceObsoleteMissions(void) override;
  // slots 0xad/0xae — 0x004eaa20/0x004eae70: AI turn tail hooks.
  void RecomputeAiExpansionAndMissionPressureScores(void) override;
  void RefreshTrackedEntriesAndReplanAiDevelopment(int unused) override;
  // slot 0x36 — 0x004e7550: forward to slots 0x4d/0x4e when city exists.
  void FinishCityPhase(void) override;
  // slot 0x67 — 0x004e7680: need assignment with capability caps / escalation roll.
  void SetTradeOffersFor(short resourceKind, short offerContext) override;
  // slot 0x9f — 0x004e7cc0: war-transition propagation across eligible allied nations.
  int ConsiderWarOfIntervention(int targetNation, int sourceNation) override;
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
  // slot 0x83 — 0x004e9f10: prune enemyFlags; true while any stays active.
  char HasEnemy(void) override;
  // slot 0x84 — 0x004e9ff0: mark a candidate nation (and its port zone) active.
  void SetEnemy(int targetNation) override;
  // slot 0x85 — 0x004ea0e0: clear a candidate nation (and its port zone).
  void StopBeingEnemiesWith(int targetNation) override;
  // slot 0xa0 — 0x004e7ec0: war-transition propagation for a nation pair.
  int ConsiderWarOfAlliance(int targetNation, int sourceNation,
                                             char swapRoles) override;
  char UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  char PassesDiplomacyStrengthThresholdForTarget(int targetNation) override;
  void AddColony(int targetNation) override;
  // slots 0xb0/0xb1 — 0x004ea430/0x004ea450: no-op overrides for AI nations.
  void AnnounceLater(short orderKind, short payload, short flags) override;
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void) override;

  void DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) override;
  // slot 0x6a — 0x004e7970: AI leaves the base 1c6→250 snapshot empty.
  void RememberTradeBids(void) override;
  // slot 0x80 — 0x004e7ca0.
  void ShowNewspaperForRecordNation() override;
  virtual void RaiseNeedPlanningMetrics(int needSlot);
  // slot 0xb3 — 0x004ea990: free every queued mission.
  virtual void KillMissions();

  void AssignUnitsToMissions(int unused);

  void UpdateTrackedEntryEligibilityByClassMaskAndRatio(int unused);

  // Chooses and applies city/industry development actions while resource pools remain.
  void PlanAiDevelopmentActionsFromResourcePools(int unused);
  float ComputeAiIndustryActionCostFromSlot(short industrySlot);
  float ComputeAiCityActionCostFromSlotAndMode(short actionSlot, bool skipContextBias);
  float GetCachedAiCityActionContextBias(short selector);

  void CreateMission(eMissionType missionType, int mapNodeIndex, TZone* zoneContext,
                     int relatedMapNodeIndex);
  void RemoveMission(eMissionType missionType, int key, TZone* zoneContext);
  void MReassess();
  void AssignMilitiaToDefendMissions();
  void CreateInitialMissions();
  void MarkEnemyProvinceCandidates();
  void SetZoneStatus(int contextOrdinal, eMissionDesirability value); // 0x4e8bf0
  void SetConquerLust(int nationSlot, char makeEnemy); // 0x004e8300
  void SetProvinceStatus(int provinceIndex, eMissionDesirability status); // Mac oracle
  void SetProvinceStatus(int provinceIndex, eMissionDesirability status, unsigned char bypassGate);

  short actionMetricByQuarter[6];
  // eMissionDesirability bytes.
  unsigned char provinceStatus[0x180];
  unsigned char zoneStatus[0x70];
  TSortedList* missionQueue;
  float expansionPressurePerCompatibleRegion;
  float averageUnitDivergencePerOwnedRegion;
  float activeMissionPressureAverageB6c;
};
ASSERT_SIZE(TAutoGreatPower, 0xb70);

bool SelectBestCityDevelopmentFromResourcePools(int nationSlot, int* resourcePools,
                                                TMilitaryUnit** bestUnitByType,
                                                char* selectedIsIndustry, char* selectedIsUpgrade,
                                                int* selectedSlot, int unused,
                                                float* selectedWeightedCost);

int ComputeBestNationTileDevelopmentScore(NationSlot nationSlot);
