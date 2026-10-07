#pragma once

#include "game/map_domain_types.h"
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

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;
  void BecomeProtectorateOf(int targetNationSlot) override;
  void AddProvince(int regionId) override;
  void PurchaseItem(short resourceKind, short amount, short price) override;
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  void AddNoticeFrom(short sourceNation, short actionCode) override;
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void) override;
  void MoveCivilians(void) override;
  void MoveArmy(void) override;
  void InitializeTradeStatus(void) override;
  void SetTradeBids(void) override;
  bool SetDiplomacyPolicyTo(short targetClass, short policyCode) override;
  void ReplyToDiplomacyOffers(void) override;
  void DeclareWarOn(int targetNationSlot, int transitionMode, int sourceNationSlot) override;
  void SelectAndQueueAdvisoryMapMissions(void) override;
  void ReplaceObsoleteMissions(void) override;
  void RecomputeAiExpansionAndMissionPressureScores(void) override;
  void ReassessMissions(int unused) override;
  void FinishCityPhase(void) override;
  void SetTradeOffersFor(short resourceKind, short offerContext) override;
  int ConsiderWarOfIntervention(int targetNation, int sourceNation) override;
  void SorryYouLose(void) override;
  void LoseProvince(int regionId) override;
  bool ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  void FillInteriorMinisterOrders(void) override;
  void ClearTradeOffers(void) override;
  void SetDiplomacyPolicies() override;
  bool HasEnemy(void) override;
  void SetEnemy(int targetNation) override;
  void StopBeingEnemiesWith(int targetNation) override;
  int ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles) override;
  bool UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  bool PassesDiplomacyStrengthThresholdForTarget(int targetNation) override;
  void AddColony(int targetNation) override;
  void AnnounceLater(short orderKind, short payload, short flags) override;
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void) override;

  void DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) override;
  void RememberTradeBids(void) override;
  void ShowNewspaperForRecordNation() override;
  virtual void RaiseNeedPlanningMetrics(int needSlot);
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
  void SetZoneStatus(int contextOrdinal, eMissionDesirability value);
  void SetConquerLust(int nationSlot, char makeEnemy);
  void SetProvinceStatus(int provinceIndex, eMissionDesirability value);
  void SetProvinceStatus(int provinceIndex, eMissionDesirability status, unsigned char bypassGate);

  short actionMetricByQuarter[6];
  // eMissionDesirability bytes.
  unsigned char provinceStatus[kProvinceCount];
  unsigned char zoneStatus[112];
  TSortedList* missionQueue;
  float expansionPressurePerCompatibleRegion;
  float averageUnitDivergencePerOwnedRegion;
  float activeMissionPressureAverage;
};
ASSERT_SIZE(TAutoGreatPower, 0xb70);

bool SelectBestCityDevelopmentFromResourcePools(int nationSlot, int* resourcePools,
                                                TMilitaryUnit** bestUnitByType,
                                                char* selectedIsIndustry, char* selectedIsUpgrade,
                                                int* selectedSlot, int unused,
                                                float* selectedWeightedCost);

int ComputeBestNationTileDevelopmentScore(NationSlot nationSlot);
