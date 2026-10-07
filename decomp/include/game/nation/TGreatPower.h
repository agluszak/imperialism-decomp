#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/core/CString.h"
#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMission.h"
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
  signed char byAction[13];

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
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;
  void MultiWriteTo(TStream* stream) override;
  void MultiReadFrom(TStream* stream, int unusedArg) override;

  // ---- diplomacy grants / policies / proposal queue ----
  void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) override;
  void ChangeMaster(int targetNationSlot, int mode) override;
  void BecomeProtectorateOf(int targetNationSlot) override;
  void LoseProvince(int regionId) override;
  void AddProvince(int regionId) override;
  void NewStatusFor(int targetNationSlot, int policyCode) override;
  void DeliverItem(short amount) override;
  short GetAmtUnsold(short resourceKind) override;
  short GetMerchantCapacity(void) override;
  short GetStockpile(short resourceKind) override;
  short GetTradeOffersFor(short resourceKind) override;
  void PurchaseItem(short resourceKind, short amount, short price) override;
  bool StillBuyingItem(ResourceKindStorage resourceKind) override;
  bool ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  void AddNoticeFrom(short sourceNation, short actionCode) override;
  virtual void NoOpNationPendingActionHook(void);

  virtual void MarkStatus5Handled(void);
  virtual void MarkAllPendingStatusFlagsHandled(void);
  virtual void DispatchPendingStatusPrompts(void);
  virtual void SetNationPendingActionStateAndPayload(int index, short payload);
  virtual void AddTurnStartEvent(TTurnStartEvent* event);
  virtual void DisplayTurnStartEvents();
  virtual void NoOpNationQueuedOrderHook(void);
  virtual void ExecuteNationPendingActionStateMachine(void);
  void PlaceCity(short homeTileIndex, char* cityName);
  virtual bool HasDeveloper(void);
  virtual void TraceSupplyRoutes(char** outInfluenceMap);
  virtual void TraceRail(char* regionMap, short regionId);

  char* MakeConnectionMap();

  // ---- turn-event message dispatch ----
  virtual void FinishCityPhase(void);
  virtual void CalculatePotentials(void);
  virtual void FillInteriorMinisterOrders(void);
  virtual void PlaceScenarioCapital(class TCity* mgr);
  virtual void CreateFrogCityTownMarkerAndAttach(void* receiver);
  virtual void CreateFrogCityAtHomeRegionAndAttach(void* receiver);
  virtual void ShowStatusMessage2(CString* message);
  virtual void ShowStatusMessage1(CString* message);
  virtual void ShowStatusMessage0(CString* message);
  // ORACLE: Mac TGreatPower::UpdateCountryStockpile(short*); the base body is empty.
  virtual void UpdateCountryStockpile(short* needVector);
  virtual unsigned int GetUnreservedMerchantCapacity(int proposalCode);
  virtual void AddTransportedItems(void);
  virtual void AddPurchasedItems(void);

  virtual void AddCreatedItems(void);
  virtual void SetNationResourceNeedCurrentByType(int needType, short currentValue);
  virtual void UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value);
  virtual bool IsNeedTargetEqualCurrent(short needIndex);
  virtual short GetNeedTargetByType(short needIndex);
  virtual void RaiseNeedTarget(int needType);
  virtual bool IsTransportCapacityExceeded(void);
  virtual bool IncreaseRollingStock(void);
  virtual bool IncreaseMerchantMarine(void);
  virtual void ContinueCivilianOrders(void);
  virtual void CountResourceYields(void);
  virtual void AdvanceRegionDevelopment(void);
  virtual bool HasExcessNeeds(void);
  virtual bool HasAnyCommodityRecordBelowStepValue(void);
  virtual short ComputeTreasuryStatusPromptCode(void);
  virtual bool IsCapitolThreatened(int mode);
  virtual bool BuildZoneEventMessages(CString* outMessageText);
  virtual bool BuildCityEventMessages(CString* outMessageText);
  virtual void SortTrackedOrdersByTypePriority(void);
  virtual void MoveCivilians(void);
  virtual void MoveArmy(void);
  virtual void TellColoniesToBoycott(int targetNationSlot, int isBoycottEnabled);
  virtual void ComputeAidBudget(void);
  virtual void InitializeTradeStatus(void);
  virtual void RecallTradeBids(void);
  virtual void InitializeDealBook(void);
  virtual void AddOverseasProfitFrom(int amount, short columnIndex, short rowIndex);
  virtual int GetOverseasProfitFrom(NationSlot targetNationSlot);
  virtual int GetTotalOverseasProfits(void);
  virtual int ComputeRemainingDiplomacyAidBudget(void);
  virtual void SetTradeBids(void);
  virtual void FillTradePartners(void);
  virtual void SetStockpile(short targetSlot, short value);
  virtual void AddToStockpile(short targetSlot, short value);
  virtual unsigned int ComputeProductionMetricForOrderKind(short orderKind);
  virtual void ConsumeMerchantCapacityForPurchase(short delta);
  virtual void SetTradeOffersFor(short resourceKind, short offerContext);
  virtual bool WereAllOfferedGoodsSold(void);
  virtual void SetItemPotentials(short resourceKind, short value);
  virtual void RememberTradeBids(void);
  virtual void ClearTradeOfferForResource(short targetSlot);
  virtual void AddToDealBook(short kind, NationSlot targetNation, short value, short slotIndex,
                             int payload);
  virtual short GetNumDealsIn(short targetSlot);
  virtual bool WasItemDeclined(short targetSlot);
  virtual void GetDealInfo(short slotIndex, short ordinal, short* outKind, short* outValue,
                           short* outTargetNation, int* outPayload);
  virtual void DealInterupted(int targetSlot, int matchKey, int payload);
  virtual void ClearTradeOffers(void);
  virtual void SetDiplomacyPolicies();
  virtual void ResetPolicies(void);
  virtual bool SetDiplomacyPolicyTo(short targetClass, short policyCode);
  virtual bool SetGrantPolicyTo(int targetNation, int grantValue);
  virtual void GiveGrantTo(int targetNationSlot);
  virtual bool CanAffordGrantTo(NationSlot targetNationSlot, unsigned short proposedGrantEntry);
  virtual void FinishDiplomacyPhase();
  virtual void ImproveTradePolicyTo(NationSlot nationSlot);
  virtual bool CanAfford(short additionalCost);
  virtual void AcceptOffer(short proposalIndex);
  virtual void RejectOffer(short proposalQueueIndex);
  virtual bool IsProposalAllowed(DiplomacyProposalCodeStorage proposalCode, int targetNation);
  virtual void InitializeDiplomacyOffers(void);
  virtual void InitializeDiplomacyNotices(void);
  virtual void ShowNewspaperForRecordNation(void);
  virtual void ReplyToDiplomacyOffers(void);
  virtual int ClassifyNationProductionTierVsPeers(void);

  virtual bool HasEnemy(void);
  virtual void SetEnemy(int targetNation);
  virtual void StopBeingEnemiesWith(int targetNation);
  virtual int GetArmsInNavy(void);
  virtual int CountMapActionContextNodesWithNationBit(void);
  virtual double GetWarNumber(void);
  virtual double GetSeekAllianceNumber(void);
  virtual double GetAcceptAllianceNumber(void);
  virtual double GetSeekPeaceNumber(void);
  virtual double GetAcceptPeaceNumber(void);
  virtual int GetBuildingCapacity(short buildingSlot);

  virtual int GetReinforcementPotential(void);
  virtual float GetMilitaryPower(void);
  virtual float GetTotalNavalForce(void);
  virtual float ComputeArmyScoreRatioVsNation(int targetNation);
  virtual float ComputeArmyScoreStandingRatioVsNation(int targetNation);
  virtual float ComputeNavyScoreRatioVsNation(int targetNation);
  virtual float ComputeNavyScoreStandingRatioVsNation(int targetNation);
  virtual float GetArmyRatioWithAlly(int targetNation, int secondarySlot);
  virtual float GetArmyStandingRatioVsPair(int targetNation, int partnerNation);
  virtual float GetNavyRatioWithAlly(int targetNation, int secondarySlot);
  virtual float GetNavyStandingRatioVsPair(int targetNation, int partnerNation);
  virtual float ComputeArmyScoreRatioForNationPair(int nationA, int nationB, char swapRoles);
  virtual float GetArmyStandingRatioForPair(int nationA, int nationB, char swapRoles);
  virtual float ComputeNavyScoreRatioForNationPair(int nationA, int nationB, char swapRoles);
  virtual float GetNavyStandingRatioForPair(int nationA, int nationB, char swapRoles);
  virtual bool IsStrongEnoughFor(int targetNation);
  virtual bool ConsiderJoiningWar(int targetNation);
  virtual int ConsiderWarOfIntervention(int targetNation, int sourceNation);
  virtual int ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles);
  virtual void DeclareWarOn(int targetNationSlot, int transitionMode, int sourceNationSlot);
  virtual void SelectAndQueueAdvisoryMapMissions(void);
  virtual float GetPeaceThreat(int targetNation);
  virtual void ReplaceObsoleteMissions();
  virtual void ClearCivilianOrders(void);
  virtual void KillUnitsIn(int ownerClass);
  virtual void AddColony(int targetNation);
  virtual void TellColoniesAboutNewEnemy(int targetNation);
  virtual void TellColoniesAboutNewPeace(int targetNation);
  virtual void TellColoniesAboutNewTreaty(int targetNationSlot, DiplomacyRelationship relationship);
  virtual void SorryYouLose(void);
  virtual int SumCommodityRecordAccumulatedValues(void);
  virtual void AssessExpansion(void);
  virtual void ReassessMissions(int unused);
  virtual bool CheckBankruptcy(void);
  virtual void AnnounceLater(short orderKind, short payload, short flags);
  virtual void ShowTurnMessages(void);

  int GetNavalMobility();
  int GetDiplomacyScore();

  void AddPurchasedItemAmount(short index, short delta);

  int ComputeAvailableDiplomacyBudget() const {
    int availableBudget = treasuryValue + diplomacyBudgetBase / 100;
    return availableBudget & (static_cast<int>(availableBudget <= 0) - 1);
  }

  TForeignMinister* foreignMinister;
  TCityInteriorMinister* interiorMinister;
  TDefenseMinister* defenseMinister;
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
  int aidAllocationMatrix[368];
  int budgetPoolBase;
  int budgetPoolDelta;
  TPtrList* turnEventQueue;
  TPtrList* proposalQueue;
  TPtrList* diplomacyTrackedSlots[17];
  TCity* city;
  TSortedList* townMarkerList;
  TSortedList* trackedObjectList;
  unsigned char enemyFlags[kNationSlotCount];
  unsigned char scenarioInitFlag;
  unsigned char pad_8b8[0x8c8 - 0x8b8];
  PendingActionStatusBlock pendingActionStatus;
  unsigned char field8d5;
  short pendingActionPayload[13];
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
  TSortedList* turnStartEvents; // owns TTurnStartEvent payloads
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
  // Object ends here at 0x964; TAutoGreatPower's AI tail follows in that subclass.

  short ComputeNationRuntimeAdvisoryMetricCase6();

  int GetMilitaryRank();

  TGreatPower();

  void SellStockToCoverDebt(void);
  int GetTotalGrants();
  float ScoreZone(TZone* zone);
  float ScoreProvinceFactor(int metricCase, int cityIndex, TZone* zone, int selectedNationSlot);
  float ScoreProvinceByMode(int cityRecordIndex, int mode, int linkCityRecordIndex);
  float ComputeAdvisoryMapNodeCompositeScore(int cityRecordIndex, int mode);
  int GetNavalForceIn(TZone* zone);
  int SumNavyOrderPriorityForNation();
  void IGreatPower(short nationSlotIndex, short humanControlledFlag);

  void GenerateGameScore(void);

  void PayForMilitary();

  TCity* GetCityState(void) {
    return city;
  }
};
ASSERT_SIZE(TGreatPower, 0x964);
