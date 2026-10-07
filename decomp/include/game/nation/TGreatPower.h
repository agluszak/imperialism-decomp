#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/core/CString.h"
#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMission.h" // eMissionType
#include "game/ui_core/TSortedList.h"

struct CRuntimeClass;
class TStream;

class TMinister;
class TForeignMinister;
class TDefenseMinister;
class TCityInteriorMinister;
class TPtrList;
class TCity;
class TZone;
class TTurnStartEvent;

// 16-bit discriminator stored in each diplomacy tracked-slot record.
enum eTrackedSlotEntryKind { kTrackedSlotAcceptEntry = 0, kTrackedSlotOfferEntry = 1 };

// The 13 pending-action status bytes at TGreatPower+0x8c8 are one indexed table.
struct PendingActionStatusBlock {
  signed char byAction[0x0d];

  short GetSerializedPrefixWord(int wordIndex) const {
    int byteIndex = wordIndex * 2;
    unsigned short lowByte = static_cast<unsigned char>(byAction[byteIndex]);
    unsigned short highByte = static_cast<unsigned char>(byAction[byteIndex + 1]);
    return static_cast<short>(lowByte | (highByte << 8));
  }
};

ASSERT_SIZE(PendingActionStatusBlock, 0x0d);

// VTABLE: IMPERIALISM 0x00653938
class TGreatPower : public TCountry {
public:
  DECLARE_DYNCREATE(TGreatPower)
  // FUNCTION: IMPERIALISM 0x004d8c50
  ~TGreatPower() override {}
  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d9c70
  void ReadFrom(TStream* stream) override; // body 0x004d92e0
  void Free() override;                    // body 0x004d9160
  void WriteCoreFieldsToStream(TStream* stream) override;
  void ReadCoreFieldsFromStream(TStream* stream, int unusedArg) override;

  // ---- diplomacy grants / policies / proposal queue ----
  void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) override;
  void ChangeMaster(int targetNationSlot, int mode) override;
  void BecomeProtectorateOf(int targetNationSlot) override; // slot 0x14
  void LoseProvince(int regionId) override;
  void AddProvince(int regionId) override;
  void NewStatusFor(int targetNationSlot, int policyCode) override;
  void DeliverItem(short amount) override;
  // ORACLE: Mac TGreatPower::GetAmtUnsold(short).
  short GetAmtUnsold(short resourceKind) override; // slot 0x1c
  short GetMerchantCapacity(void) override;        // slot 0x1d
  // ORACLE: Mac TGreatPower::GetStockpile(short).
  short GetStockpile(short resourceKind) override; // slot 0x1e
  // ORACLE: Mac TGreatPower::GetTradeOffersFor(short).
  short GetTradeOffersFor(short resourceKind) override; // slot 0x1f
  void PurchaseItem(short resourceKind, short amount, short price) override;
  bool StillBuyingItem(ResourceKindStorage resourceKind) override; // slot 0x21
  bool ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  // ORACLE: Mac names TGreatPower::AddOfferFrom(short, short).
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  // ORACLE: Mac names TGreatPower::AddNoticeFrom(short, short).
  void AddNoticeFrom(short sourceNation, short actionCode) override; // slot 0x94
  virtual void NoOpNationPendingActionHook(void);

  virtual void MarkStatusFlag5HandledIfCapabilityActive(void);
  virtual void MarkAllPendingStatusFlagsHandled(void);
  virtual void DispatchPendingStatusPrompts(void);
  virtual void SetNationPendingActionStateAndPayload(int index, short payload); // slot 0x2e
  // slot 0x2f — Mac oracle: AddTurnStartEvent(TTurnStartEvent*); the base queues it.
  virtual void AddTurnStartEvent(TTurnStartEvent* event);
  // slot 0x30 — executes every queued event in order, then frees them.
  // ORACLE: Mac TGreatPower::DisplayTurnStartEvents().
  virtual void DisplayTurnStartEvents();
  virtual void NoOpNationQueuedOrderHook(void);
  virtual void ExecuteNationPendingActionStateMachine(void);
  void PlaceCity(short homeTileIndex, char* cityName);
  virtual bool HasDeveloper(void);
  virtual void BuildTransportLinkedInfluenceMap(char** outInfluenceMap);
  virtual void TraceRail(char* regionMap, short regionId);

  char* BuildCityInfluenceLevelMap();

  // ---- turn-event message dispatch ----
  virtual void FinishCityPhase(void);
  virtual void CalculatePotentials(void);
  virtual void FillInteriorMinisterOrders(void);
  virtual void ApplyScenarioRelationPresetAndSpawnFrogCity(class TCity* mgr);
  virtual void CreateFrogCityTownMarkerAndAttach(void* receiver);
  virtual void CreateFrogCityAtHomeRegionAndAttach(void* receiver);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message);
  // slot 0x3f / vtable offset 0xfc — TCity::PredictedNeeds passes its 23-entry
  // city-stock vector here. The base implementation is a bare `ret 4`.
  // ORACLE: Mac names TGreatPower::UpdateCountryStockpile(short*).
  virtual void UpdateCountryStockpile(short* needVector);
  virtual unsigned int GetMerchantCapacityForProposal(int proposalCode);
  // ORACLE: Mac names TGreatPower::AddTransportedItems().
  virtual void AddTransportedItems(void); // slot 0x41
  // ORACLE: Mac names TGreatPower::AddPurchasedItems().
  virtual void AddPurchasedItems(void); // slot 0x42

  // ---- resource needs / aid allocation ----
  // ORACLE: Mac names TGreatPower::AddCreatedItems().
  virtual void AddCreatedItems(void);
  virtual void SetNationResourceNeedCurrentByType(int needType, int currentValue);
  virtual void UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value); // slot 0x45
  virtual bool IsNeedTargetEqualCurrent(short needIndex);                          // slot 0x46
  virtual short GetNeedTargetByType(short needIndex);                              // slot 0x47
  virtual void TryIncrementNationResourceNeedTargetTowardCurrent(int needType);
  virtual bool IsTransportCapacityExceeded(void);
  virtual bool IncreaseRollingStock(void);   // slot 0x4a
  virtual bool IncreaseMerchantMarine(void); // slot 0x4b
  // slot 0x4c — body 0x004e0220: invokes [vt+0x2c] on every tracked order.
  virtual void ContinueCivilianOrders(void); // slot 0x4c
  virtual void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  virtual void AdvanceOwnedRegionDevelopmentCountersAndHandleEvents(void);
  virtual bool AnyNeedCurrentExceedsTargetWhenCapMismatch(void); // slot 0x4f
  virtual bool HasAnyCommodityRecordBelowStepValue(void);
  virtual short ComputeTreasuryStatusPromptCode(void);
  virtual bool IsCapitolThreatened(int mode);
  virtual bool BuildGreatPowerMapContextTriggeredNationEventMessages(CString* outMessageText);
  virtual bool BuildGreatPowerEligibleNationEventMessagesFromLinkedList(CString* outMessageText);
  virtual void SortTrackedOrdersByTypePriority(void);
  // slot 0x56 — body 0x004e03a0: runs slot 0x4c then the slot 0x55 sort.
  virtual void MoveCivilians(void); // Mac oracle
  // slot 0x57 — body 0x004e03d0: armyTransportRemaining = transportCapacity / 5.
  virtual void MoveArmy(void); // Mac oracle
  virtual void SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(int targetNationSlot,
                                                                            int isBoycottEnabled);
  virtual void RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void);
  virtual void InitializeTradeStatus(void);
  // ORACLE: Mac names TGreatPower::RecallTradeBids().
  virtual void RecallTradeBids(void);
  virtual void InitializeDealBook(void); // slot 0x5c
  virtual void AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                          short rowIndex);
  virtual int SumAidAllocationMatrixColumnForTarget(NationSlot targetNationSlot);
  virtual int SumAidAllocationMatrixAllCells(void); // slot 0x5f
  virtual int ComputeRemainingDiplomacyAidBudget(void);
  virtual void SetTradeBids(void);
  virtual void AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void);
  virtual void SetCityStockCounterAndRefresh(short targetSlot, short value);   // slot 0x63
  virtual void AddToCityStockCounterAndRefresh(short targetSlot, short value); // slot 0x64
  virtual unsigned int ComputeProductionMetricForOrderKind(short orderKind);
  virtual void ConsumeMerchantCapacityForPurchase(int delta);             // slot 0x66
  virtual void SetTradeOffersFor(short resourceKind, short offerContext); // slot 0x19c
  virtual bool AreAdvancedManufacturedTradeOffersExhausted(void);         // slot 0x68
  // ORACLE: Mac TGreatPower::SetItemPotentials(short, short).
  virtual void SetItemPotentials(short resourceKind, short value); // slot 0x69
  // ORACLE: Mac names TGreatPower::RememberTradeBids().
  virtual void RememberTradeBids(void); // slot 0x6a
  // slot 0x6b / 0x1ac — body 0x004ddd20: clears itemPotentials[targetSlot].
  virtual void ClearTradeOfferForResource(short targetSlot);
  // slot 0x6c — body 0x004ddd90: packs {kind, targetNation, value, eligibility,
  // payload} and appends it to diplomacyTrackedSlots[slotIndex] via [vt+0x38];
  // Offer entries are always eligible; accept entries are eligible for minor nations.
  // ORACLE: Mac names this TGreatPower::AddToDealBook(short, short, short, short, long).
  virtual void AddToDealBook(short kind, NationSlot targetNation, short value, short slotIndex,
                             int payload);
  virtual short GetTrackedSlotEntryCountLow(short targetSlot);     // slot 0x6d
  virtual bool AnyTrackedSlotEntryHasZeroField4(short targetSlot); // slot 0x6e
  // slot 0x6f — body 0x004ddeb0: unpacks tracked-slot entry fields (+0/+2/+4/+8).
  virtual void GetDealInfo(short slotIndex, short ordinal, short* outKind, short* outValue,
                           short* outTargetNation, int* outPayload);
  virtual void AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                             int payload); // slot 0x70
  virtual void ClearTradeOffers(void);                                     // index 113
  // ORACLE: Mac names TGreatPower::SetDiplomacyPolicies().
  virtual void SetDiplomacyPolicies();                                           // index 114
  virtual void ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void); // index 115
  virtual bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                                short policyCode);   // index 116
  virtual bool SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2); // index 117
  // ORACLE: Mac names TGreatPower::GiveGrantTo(short).
  virtual void GiveGrantTo(int sourceNation); // index 118
  virtual bool
  CanAffordDiplomacyGrantEntryForTarget(NationSlot targetNationSlot,
                                        unsigned short proposedGrantEntry); // index 119
  // ORACLE: Mac names TGreatPower::FinishDiplomacyPhase().
  virtual void FinishDiplomacyPhase();                                // index 120 — body 0x004de7e0
  virtual void DecrementNeedLevelByNationStep(NationSlot nationSlot); // index 121
  virtual bool CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost); // index 122
  virtual void AcceptOffer(short proposalIndex);                                       // index 123
  virtual void RejectOffer(short proposalQueueIndex);                                  // index 124
  virtual bool IsDiplomacyProposalAllowedForRelationship(DiplomacyProposalCodeStorage proposalCode,
                                                         int targetNation);
  virtual void InitializeDiplomacyOffers(void);
  virtual void InitializeDiplomacyNotices(void);
  virtual void ShowNewspaperForRecordNation(void);
  virtual void ReplyToDiplomacyOffers(void);
  virtual int ClassifyNationProductionTierVsPeers(void);

  virtual bool HasEnemy(void);
  // index 132 / vtable+0x210. Evidence: 0x004e9ed0 calls this on `this`
  // with one target-nation argument; return value ignored.
  // ORACLE: Mac names TGreatPower::SetEnemy(long) and StopBeingEnemiesWith(long).
  virtual void SetEnemy(int targetNation);             // body 0x004e0420
  virtual void StopBeingEnemiesWith(int targetNation); // index 133 — body 0x004e0440
  // ORACLE: Mac TGreatPower::GetArmsInNavy().
  virtual int GetArmsInNavy(void);
  virtual int CountMapActionContextNodesWithNationBit(void); // slot 0x87
  // ORACLE: Mac names the five war/alliance/peace threshold queries below.
  virtual double GetWarNumber(void);            // slot 0x88
  virtual double GetSeekAllianceNumber(void);   // slot 0x89
  virtual double GetAcceptAllianceNumber(void); // slot 0x8a
  virtual double GetSeekPeaceNumber(void);      // slot 0x8b
  virtual double GetAcceptPeaceNumber(void);    // slot 0x8c
  // ORACLE: Mac TGreatPower::GetBuildingCapacity(short).
  virtual int GetBuildingCapacity(short buildingSlot); // slot 0x8d

  // ---- relative military/naval power scoring ----
  // Relative military/naval power score family (bodies 0x004e07b0..0x004e1c20).
  // ORACLE: Mac TGreatPower::GetReinforcementPotential().
  virtual int GetReinforcementPotential(void);
  // ORACLE: Mac TGreatPower::GetMilitaryPower().
  virtual float GetMilitaryPower(void);
  // ORACLE: Mac TGreatPower::GetTotalNavalForce().
  virtual float GetTotalNavalForce(void);
  virtual float ComputeArmyScoreRatioVsNation(int targetNation);         // slot 0x91
  virtual float ComputeArmyScoreStandingRatioVsNation(int targetNation); // slot 0x92
  virtual float ComputeNavyScoreRatioVsNation(int targetNation);         // slot 0x93
  virtual float ComputeNavyScoreStandingRatioVsNation(int targetNation); // slot 0x94
  virtual float ComputeArmyScoreRatioVsNationWithSecondary(int targetNation,
                                                           int secondarySlot); // slot 0x95
  virtual float ComputeArmyScoreStandingRatioVsNationPair(int targetNation,
                                                          int partnerNation); // slot 0x96
  virtual float ComputeNavyScoreRatioVsNationWithSecondary(int targetNation,
                                                           int secondarySlot); // slot 0x97
  virtual float ComputeNavyScoreStandingRatioVsNationPair(int targetNation,
                                                          int partnerNation); // slot 0x98
  virtual float ComputeArmyScoreRatioForNationPair(int nationA, int nationB,
                                                   char swapRoles); // slot 0x99
  virtual float ComputeArmyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                           char swapRoles); // slot 0x9a
  virtual float ComputeNavyScoreRatioForNationPair(int nationA, int nationB,
                                                   char swapRoles); // slot 0x9b
  virtual float ComputeNavyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                           char swapRoles); // slot 0x9c
  virtual bool PassesDiplomacyStrengthThresholdForTarget(int targetNation); // body 0x004e1c00
  virtual bool EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation);
  virtual int ConsiderWarOfIntervention(int targetNation, int sourceNation); // slot 0x27c
  virtual int ConsiderWarOfAlliance(int targetNation, int sourceNation,
                                    char swapRoles); // slot 0x280
  virtual void QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot,
                                                             int transitionMode,
                                                             int sourceNationSlot);
  virtual void SelectAndQueueAdvisoryMapMissions(void); // body 0x004e1f20
  virtual float GetPeaceThreat(int targetNation);
  virtual void ReplaceObsoleteMissions(); // slot 0xa4 — body 0x004e2190
  // ORACLE: Mac names TGreatPower::ClearCivilianOrders().
  virtual void ClearCivilianOrders(void);
  // slot 0x298 — fired by RemoveRegionIdAndRunTrackedObjectCleanup (0x004e2270).
  // ORACLE: Mac names TGreatPower::KillUnitsIn(long).
  virtual void KillUnitsIn(int regionId);
  virtual void AddColony(int targetNation);
  virtual void DeclareWarOnTargetForAlignedMinors(int targetNation);
  virtual void MakePeaceWithTargetForAlignedMinors(int targetNation);
  virtual void DispatchNationDiplomacySlotActionByMode(int targetNationSlot,
                                                       DiplomacyRelationship relationship);
  virtual void SorryYouLose(void);
  virtual int SumCommodityRecordAccumulatedValues(void);
  virtual void RecomputeAiExpansionAndMissionPressureScores(void);
  virtual void RefreshTrackedEntriesAndReplanAiDevelopment(int unused);
  virtual bool UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  // ORACLE: Mac names TGreatPower::AnnounceLater(short, short, short).
  virtual void AnnounceLater(short orderKind, short payload, short flags);
  virtual void BuildGreatPowerTurnMessageSummaryAndDispatch(void);

  // LoadNationDisplayNameSharedRefFromField8 moved to TCountry (its field's owner).

  int ComputeNationNavyOrderWeightedMovementScore();
  int RecomputeNationComparativePowerMetrics_Impl();

  void AddPurchasedItemAmount(short index, short delta);

  int ComputeAvailableDiplomacyBudget() const {
    int availableBudget = treasuryValue + diplomacyBudgetBase / 100;
    return availableBudget & (static_cast<int>(availableBudget <= 0) - 1);
  }

  TForeignMinister* foreignMinister;       // +0x94
  TCityInteriorMinister* interiorMinister; // +0x98
  TDefenseMinister* defenseMinister;       // +0x9c
  unsigned char diplomacyEligibility;
  unsigned char pad_a1;
  short availableMerchantCapacity;
  short merchantCapacity;
  short transportCapacity;
  short reservedTransportCapacity;
  unsigned char pad_aa[2];
  int grantTotalCost;
  short unfilledTradeOfferCount;
  short diplomacyPolicyByNation[kNationSlotCount];
  short diplomacyGrantByNation[kNationSlotCount];
  short needCurrentByType[kResourceKindCount];
  short needTargetByType[kResourceKindCount];
  short relationDeltaCurrent[kResourceKindCount];
  short purchasedItemsByResource[kResourceKindCount];
  short itemPotentials[kResourceKindCount];
  short unfilledTradeTurnCountsByResource[kResourceKindCount];
  short transportedItemsByResource[kResourceKindCount];
  short rememberedTradeOffersByResource[kResourceKindCount];
  int aidAllocationMatrix[0x170];
  int budgetPoolBase;
  int budgetPoolDelta;
  TPtrList* turnEventQueue;
  TPtrList* proposalQueue;
  TPtrList* diplomacyTrackedSlots[0x11];
  TCity* city;
  TSortedList* townMarkerList;
  TSortedList* trackedObjectList;
  unsigned char enemyFlags[kNationSlotCount];
  unsigned char scenarioInitFlag;
  unsigned char pad_8b8[0x8c8 - 0x8b8];
  PendingActionStatusBlock pendingActionStatus;
  unsigned char field8d5;
  short field8d6[0x0d];
  int diplomacyBudgetBase;
  signed char escalationCounter;
  unsigned char pad_8f5[3];
  int pendingCommitmentCost;
  signed char pressureCounter;
  unsigned char pad_8fd[3];
  int armyTransportRemaining;
  unsigned char turnFinished;
  unsigned char pad_905[3];
  TPtrList* turnSummaryQueue;
  TSortedList* turnStartEvents; // +0x90c; owns TTurnStartEvent payloads
  int specialResourceTradeBalance;
  int aidAllocationTotal;
  unsigned char colonyBoycottFlags[kNationSlotCount];
  unsigned char pad_92f;
  enum GameScoreRow {
    kGameScoreLabor = 0,
    kGameScoreTransport = 1,
    kGameScoreIndustry = 2,
    kGameScoreProvinces = 3,
    kGameScoreMilitary = 4,
    kGameScoreNavy = 5,
    kGameScoreDiplomacy = 6,
    kGameScoreMerchantMarine = 7,
    kGameScoreYear = 8,
    kGameScoreSubtotal = 9,
    kGameScoreDifficultyPercent = 10,
    kGameScoreTotal = 11,
    kGameScoreRowCount = 12
  };
  int gameScoreRows[kGameScoreRowCount];
  int militaryExpenses;
  // Object ends here at 0x964 (== CRuntimeClass::m_nObjectSize for TGreatPower and
  // for TProxyGreatPower/TClientGreatPower/TRemoteGreatPower; THostGreatPower adds one
  // more dword). The AI-only tail block (actionMetricByQuarter/provinceStatus/
  // zoneStatus/missionQueue/floatB64/floatB68) that used to be declared here
  // moved to TAutoGreatPower (RTTI size 0xb70) -- see TSimMgr::RebuildPrimaryNationState
  // ForSlot (0x57cda0): every non-Auto concrete subclass allocates exactly its own
  // RTTI-reported size with no room for that block, and the one "bare TGreatPower"-
  // looking construction (TSimMgr.cpp, scenario mode 2) is proven by its
  // operator_new(0xb70) + TAutoGreatPower::TAutoGreatPower() ctor call (thunk 0x407a31
  // -> 0x4e6b50) to actually construct a TAutoGreatPower, not a bare TGreatPower.

  short ComputeNationRuntimeAdvisoryMetricCase6();

  int ClassifyNationMilitaryPowerBandAgainstGlobalMean();

  TGreatPower();

  void CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
  int SumDiplomacyGrantEntriesMaskedToValueBits();
  float ComputeMapActionContextCompositeScoreForNation(TZone* zone);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex, TZone* zone,
                                                      int selectedNationSlot);
  float ComputeAdvisoryMapNodeCompositeScoreByMode(int cityRecordIndex, int mode,
                                                   int linkCityRecordIndex);
  float ComputeAdvisoryMapNodeCompositeScore(int cityRecordIndex, int mode);
  int SumNavyOrderPriorityForNationAndNodeType(TZone* zone);
  int SumNavyOrderPriorityForNation();
  void IGreatPower(short nationSlotIndex, short humanControlledFlag);

  void GenerateGameScore(void); // 0x004e32a0

  void PayForMilitary();

  TCity* GetCityState(void) {
    return city;
  }
};
ASSERT_SIZE(TGreatPower, 0x964);
