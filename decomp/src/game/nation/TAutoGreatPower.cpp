#include "game/nation_domain_types.h"
#include "decomp_types.h"
#include "game/ui_tags_common.h"
#include <stdlib.h>
#include <string.h>
#include "game/navy_order.h"

#include "game/nation/TAutoGreatPower.h"

#include "game/city_ui/TCityMinisterPersonalities.h"
#include "game/military_ui/TDefenseMinisterPersonalities.h"
#include "game/nation/TForeignMinisterPersonalities.h"
#include "game/TList.h"
#include "game/navy/TOcean.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/nation_stream_serialization.h"
#include "game/ui_core/CIterator.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TPtrList.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/map/TMinister.h"
#include "game/nation/TForeignMinister.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/military_ui/TDefenseMinister.h"
#include "game/military/TDefendProvinceMission.h"
#include "game/core/TStream.h"
#include "game/map/TMission.h"
#include "game/nation/TMinor.h"
#include "game/city/TCity.h"
#include "game/globals/global_types.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TZone.h"
#include <new>

#include "game/net/TMultiplayerMgr.h"
#include "game/navy/TShip.h"
#include "game/GameAssert.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/military/TMilitaryUnit.h"
#include "game/city_ui/TProvinceDesirabilityList.h"

// kNationSlotCount (0x17) comes from TDiplomacyMgr.h.
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kPortZoneCount = 0x70;

// FUNCTION: IMPERIALISM 0x004e6b10
bool TAutoGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {
  return false;
}

IMPLEMENT_DYNCREATE(TAutoGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x004e6b50
TAutoGreatPower::TAutoGreatPower() : TGreatPower() {
  missionQueue = 0;
}

// FUNCTION: IMPERIALISM 0x004e6bb0
TAutoGreatPower::~TAutoGreatPower() {}

// FUNCTION: IMPERIALISM 0x004e6c20
void TAutoGreatPower::IAutoGreatPower(int nationSlot, int nationInitializationMode,
                                      short cityMinisterPolicyId, short foreignMinisterPolicyId,
                                      short defenseMinisterPolicyId) {
  IGreatPower(nationSlot, nationInitializationMode);
  treasuryValue = 10000;
  memset(actionMetricByQuarter, 0, sizeof(actionMetricByQuarter));

  switch (defenseMinisterPolicyId) {
  case 0: {
    TNapoleonMinister* minister = new TNapoleonMinister();
    minister->INapoleonMinister(this);
    defenseMinister = minister;
    break;
  }
  case 1: {
    TBismarckMinister* minister = new TBismarckMinister();
    minister->IBismarckMinister(this);
    defenseMinister = minister;
    break;
  }
  case 2: {
    TPirateMinister* minister = new TPirateMinister();
    minister->IPirateMinister(this);
    defenseMinister = minister;
    break;
  }
  case 3: {
    TDefenderMinister* minister = new TDefenderMinister();
    minister->IDefenderMinister(this);
    defenseMinister = minister;
    break;
  }
  case 4: {
    TBullyMinister* minister = new TBullyMinister();
    minister->IBullyMinister(this);
    defenseMinister = minister;
    break;
  }
  }

  switch (foreignMinisterPolicyId) {
  case 0: {
    TArmsForeignMinister* minister = new TArmsForeignMinister();
    minister->IForeignMinister(this);
    foreignMinister = minister;
    break;
  }
  case 1: {
    TTraderForeignMinister* minister = new TTraderForeignMinister();
    minister->IForeignMinister(this);
    foreignMinister = minister;
    break;
  }
  case 2: {
    TTextileForeignMinister* minister = new TTextileForeignMinister();
    minister->IForeignMinister(this);
    foreignMinister = minister;
    break;
  }
  case 3: {
    TDiplomatForeignMinister* minister = new TDiplomatForeignMinister();
    minister->IForeignMinister(this);
    foreignMinister = minister;
    break;
  }
  case 4: {
    TBillForeignMinister* minister = new TBillForeignMinister();
    minister->IForeignMinister(this);
    foreignMinister = minister;
    break;
  }
  case 5: {
    TTedForeignMinister* minister = new TTedForeignMinister();
    minister->IForeignMinister(this);
    foreignMinister = minister;
    break;
  }
  }

  switch (cityMinisterPolicyId) {
  case 0: {
    TSteelCityMinister* minister = new TSteelCityMinister();
    minister->ISteelCityMinister(this);
    interiorMinister = minister;
    minister->SetParameters(1, 2);
    break;
  }
  case 1: {
    TRailCityMinister* minister = new TRailCityMinister();
    minister->IRailCityMinister(this);
    interiorMinister = minister;
    minister->SetParameters(1, 2);
    break;
  }
  case 2: {
    TShipBuilderCityMinister* minister = new TShipBuilderCityMinister();
    minister->IShipBuilderCityMinister(this);
    interiorMinister = minister;
    minister->SetParameters(1, 2);
    break;
  }
  case 3: {
    TEvenCityMinister* minister = new TEvenCityMinister();
    minister->IEvenCityMinister(this);
    interiorMinister = minister;
    minister->SetParameters(1, 2);
    break;
  }
  }

  memset(provinceStatus, 0, sizeof(provinceStatus));
  memset(zoneStatus, 0, sizeof(zoneStatus));
  missionQueue = new TList();
}

// FUNCTION: IMPERIALISM 0x004e7230
void TAutoGreatPower::Free(void) {
  if (missionQueue != 0) {
    int ordinal = missionQueue->GetCount();
    for (; ordinal > 0; --ordinal) {
      TMission* entry = static_cast<TMission*>(missionQueue->GetEntryByOrdinal(ordinal));
      entry->AssertValid();
      missionQueue->RemoveAtOrdinal(ordinal);
      entry->Free();
    }
    if (missionQueue != 0) {
      missionQueue->FreeList();
    }
    missionQueue = 0;
  }
  TGreatPower::Free();
}

// FUNCTION: IMPERIALISM 0x004e72c0
void TAutoGreatPower::ReadFrom(TStream* stream) {
  TGreatPower::ReadFrom(stream);
  stream->ReadBytes(actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(actionMetricByQuarter, 6);

  stream->ReadBytes(provinceStatus, sizeof(provinceStatus));
  stream->ReadBytes(zoneStatus, 0x70);

  if (missionQueue->GetCount() != 0) {
    missionQueue->FreePayloads();
  }
  missionQueue->ReadFrom(stream);

  int missionCount;
  stream->ReadBytes(&missionCount, 4);
  for (int queueIndex = 1; queueIndex <= missionCount; ++queueIndex) {
    void* mission = 0;
    if (stream->ReadObject(&mission)) {
      missionQueue->AddTail(mission);
    }
  }

  if (g_nSaveFormatVersion < 0x39) {
    CreateMission(kMissionTypeScatteredShips, -1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e73f0
void TAutoGreatPower::WriteTo(TStream* stream) {
  TGreatPower::WriteTo(stream);

  WriteShortArrayElems(stream, actionMetricByQuarter, 6);

  stream->WriteBytes(provinceStatus, sizeof(provinceStatus));
  stream->WriteBytes(zoneStatus, 0x70);

  missionQueue->WriteTo(stream);
  int missionQueueCount = missionQueue->GetCount();
  stream->WriteBytes(&missionQueueCount, 4);
  for (int index = 1; index <= missionQueueCount; ++index) {
    stream->WriteObject(missionQueue->GetEntryByOrdinal(index), 0);
  }
}

// FUNCTION: IMPERIALISM 0x004e7510
void TAutoGreatPower::SorryYouLose(void) {
  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->SendGameControl(kControlTagLost, nationSlot, -3);
  }
}

// FUNCTION: IMPERIALISM 0x004e7550
void TAutoGreatPower::FinishCityPhase(void) {
  if (city != 0) {
    RebuildNationResourceYieldCountersAndDevelopmentTargets();
    AdvanceOwnedRegionDevelopmentCountersAndHandleEvents();
  }
}

// FUNCTION: IMPERIALISM 0x004e7590
void TAutoGreatPower::FillInteriorMinisterOrders(void) {
  if (city != 0) {
    interiorMinister->FillOrders();
  }
}

// FUNCTION: IMPERIALISM 0x004e75c0
void TAutoGreatPower::RaiseNeedPlanningMetrics(int needSlot) {
  actionMetricByQuarter[static_cast<short>(needSlot) - 7] += 4;
  SetStockpile(needSlot, GetStockpile(needSlot) + 4);
  SetItemPotentials(needSlot, GetTradeOffersFor(needSlot) + 4);
}

// FUNCTION: IMPERIALISM 0x004e7630
void TAutoGreatPower::PurchaseItem(short resourceKind, short amount, short price) {
  short resourceSlot = resourceKind;
  short resourceDelta = amount;
  if (resourceDelta < 0 && resourceSlot >= 7 && resourceSlot <= 0x0C) {
    actionMetricByQuarter[resourceSlot - 7] =
        static_cast<short>(actionMetricByQuarter[resourceSlot - 7] + resourceDelta);
  }

  TGreatPower::PurchaseItem(resourceKind, amount, price);
}

// FUNCTION: IMPERIALISM 0x004e7680
void TAutoGreatPower::SetTradeOffersFor(short resourceKind, short offerContext) {
  if (g_apNationStates[offerContext]->diplomacyEligibility != 0) {
    if (resourceKind != 5) {
      short relationScore =
          g_pDiplomacyTurnStateManager
              ->relationStandingScores[nationSlot * kNationSlotCount + offerContext];
      double scaledScore = static_cast<double>(relationScore) * 0.00392156862745098;
      int roll = rand();
      if (static_cast<double>(roll) > scaledScore * 32767.0) {
        RaiseNeedPlanningMetrics(resourceKind);
      }
      return;
    }
  } else if (resourceKind != 5) {
    short metricCap = 10;
    if (GetStockpile(resourceKind) < 10) {
      metricCap = GetStockpile(resourceKind);
    }
    if (merchantCapacity < metricCap) {
      metricCap = merchantCapacity;
    }
    if (GetTradeOffersFor(resourceKind) == -1) {
      return;
    }
    SetItemPotentials(resourceKind, metricCap);
    return;
  }
  if (GetStockpile(kResourceHorses) != 0 && GetTradeOffersFor(kResourceHorses) != -1) {
    short metric = GetStockpile(kResourceHorses);
    int assignAmount = (metric != 1) + 1;
    if (merchantCapacity < static_cast<short>(assignAmount)) {
      assignAmount = merchantCapacity;
    }
    SetItemPotentials(kResourceHorses, static_cast<short>(assignAmount));
  }
}

// FUNCTION: IMPERIALISM 0x004e7810
void TAutoGreatPower::InitializeTradeStatus(void) {
  int total = 0;
  for (int resourceType = 0; static_cast<short>(resourceType) < 0x0E; ++resourceType) {
    total += TShip::GetTypeCargoHold(resourceType) * city->orderCountByType[resourceType];
  }

  merchantCapacity = static_cast<short>(total);
  availableMerchantCapacity = static_cast<short>(total);
  unfilledTradeOfferCount = 0;
  budgetPoolDelta = 0;
  budgetPoolBase = 0;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    itemPotentials[nationIndex] = 0;
    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e78d0
void TAutoGreatPower::MoveCivilians(void) {
  interiorMinister->ProcessUnitOrders();
}

// FUNCTION: IMPERIALISM 0x004e78f0
void TAutoGreatPower::MoveArmy(void) {
  defenseMinister->DoArmyMovement();
}

// FUNCTION: IMPERIALISM 0x004e7910
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) {}

// FUNCTION: IMPERIALISM 0x004e7930
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) {}

// FUNCTION: IMPERIALISM 0x004e7950
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) {}

// FUNCTION: IMPERIALISM 0x004e7970
void TAutoGreatPower::RememberTradeBids(void) {}

// FUNCTION: IMPERIALISM 0x004e7990
void TAutoGreatPower::SetTradeBids(void) {
  foreignMinister->SetTradeBids();
  foreignMinister->DoUsualSubsidyRule();
}

// FUNCTION: IMPERIALISM 0x004e79d0
bool TAutoGreatPower::ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                        ResourceKindStorage resourceKind) {
  if (StillBuyingItem(resourceKind)) {
    foreignMinister->ReplyToTradeOffer(targetNationSlot, amount, price, resourceKind);
    return false;
  }
  AddToDealBook(kTrackedSlotOfferEntry, targetNationSlot, 0, resourceKind, 0);
  return false;
}

// FUNCTION: IMPERIALISM 0x004e7a50
void TAutoGreatPower::ClearTradeOffers(void) {
  if (city != 0) {
    foreignMinister->EndTradePhase();
    short* pendingMetric = actionMetricByQuarter;
    for (short needSlot = 7; needSlot <= 0x0c; ++needSlot) {
      short pending = *pendingMetric;
      if (pending > 0) {
        short current = GetStockpile(needSlot);
        if (current >= pending) {
          SetStockpile(needSlot, static_cast<short>(current - pending));
        } else {
          SetStockpile(needSlot, 0);
        }
      }
      *pendingMetric = 0;
      ++pendingMetric;
    }
    TGreatPower::ClearTradeOffers();
  }
}

// FUNCTION: IMPERIALISM 0x004e7af0
void TAutoGreatPower::SetDiplomacyPolicies() {
  if (city != 0) {
    foreignMinister->SetDiplomacyPolicies();
  }
}

// FUNCTION: IMPERIALISM 0x004e7b20
bool TAutoGreatPower::SetDiplomacyPolicyTo(short targetClass, short policyCode) {
  return TGreatPower::SetDiplomacyPolicyTo(targetClass, policyCode);
}

// FUNCTION: IMPERIALISM 0x004e7b50
void TAutoGreatPower::AddOfferFrom(NationSlot sourceNationSlot,
                                   DiplomacyProposalCodeStorage proposalCode) {
  switch (proposalCode) {
  case kDiplomacyProposalJoinEmpire:
  case kDiplomacyProposalNonAggressionPact:
    return;
  case kDiplomacyProposalAlliance:
  case kDiplomacyProposalJoinEmpireWithWarEntanglements: {
    bool hasAllianceGuard =
        g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(sourceNationSlot, nationSlot);
    if (!hasAllianceGuard) {
      TGreatPower::AddOfferFrom(sourceNationSlot, proposalCode);
    }
    return;
  }
  default:
    TGreatPower::AddOfferFrom(sourceNationSlot, proposalCode);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004e7be0
void TAutoGreatPower::ReplyToDiplomacyOffers(void) {
  if (city == 0) {
    return;
  }

  short rowIndex = 1;
  if (proposalQueue->GetSize() >= rowIndex) {
    do {
      foreignMinister->ReplyToDiplomacyOffers(rowIndex);
      ++rowIndex;
    } while (rowIndex <= proposalQueue->GetSize());
  }

  ResetPolicies();
}

// FUNCTION: IMPERIALISM 0x004e7c50
void TAutoGreatPower::AddNoticeFrom(short sourceNation, short actionCode) {
  // MATCH: the original guards the whole body with a null-this test.
  if (this == 0) {
    return;
  }
  if (actionCode == kDiplomacyProposalDeclareWar) {
    SetEnemy(sourceNation);
  }
  TGreatPower::AddNoticeFrom(sourceNation, actionCode);
}

// FUNCTION: IMPERIALISM 0x004e7ca0
void TAutoGreatPower::ShowNewspaperForRecordNation() {}

// FUNCTION: IMPERIALISM 0x004e7cc0
int TAutoGreatPower::ConsiderWarOfIntervention(int targetNation, int sourceNation) {
  bool allBeatable = true;
  bool beatableByNation[kMajorNationCount] = {false, false, false, false, false, false, false};
  int nation = 0;
  while (allBeatable) {
    if (nation >= kMajorNationCount) {
      break;
    }
    if (g_pSimMgr->ReallyInTheGame(nation) && nation != nationSlot) {
      if (!g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, nation) &&
          g_pDiplomacyTurnStateManager->AreAtWar(targetNation, nation)) {
        bool borderLinked = g_pGlobalMapState->AreNationsBorderLinked(targetNation, nationSlot);
        float combinedScore;
        if (borderLinked != 0) {
          combinedScore = ComputeArmyScoreRatioVsNationWithSecondary(sourceNation, targetNation);
          combinedScore =
              ComputeArmyScoreStandingRatioVsNationPair(sourceNation, targetNation) + combinedScore;
        } else {
          combinedScore = ComputeNavyScoreRatioVsNationWithSecondary(sourceNation, targetNation);
          combinedScore =
              ComputeNavyScoreStandingRatioVsNationPair(sourceNation, targetNation) + combinedScore;
        }
        if (GetWarNumber() > combinedScore) {
          allBeatable = false;
        } else {
          beatableByNation[nation] = true;
        }
      }
    }
    ++nation;
  }
  if (allBeatable) {
    for (int helperNation = 0; helperNation < kMajorNationCount; ++helperNation) {
      if (beatableByNation[helperNation]) {
        DeclareWarOn(helperNation, 1, targetNation);
      }
    }
    TMinor* minor = g_apSecondaryNationStateSlots[targetNation];
    short ownerSlot = minor->encodedNationSlot;
    if (ownerSlot >= 200) {
      ownerSlot -= 200;
    } else if (ownerSlot >= 100) {
      ownerSlot -= 100;
    } else {
      ownerSlot = minor->nationSlot;
    }
    if (ownerSlot != nationSlot) {
      minor->ChangeMaster(nationSlot, 1);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e7ec0
int TAutoGreatPower::ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles) {
  bool hasPolicy = false;
  if (swapRoles == 0) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, sourceNation)) {
      hasPolicy = true;
    }
  } else {
    if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, targetNation)) {
      hasPolicy = true;
    }
  }
  if (!hasPolicy) {
    bool borderLinked = g_pGlobalMapState->AreNationsBorderLinked(sourceNation, nationSlot);
    float ratioScore;
    float standingScore;
    if (borderLinked != 0) {
      ratioScore = ComputeArmyScoreRatioForNationPair(sourceNation, targetNation, swapRoles);
      standingScore =
          ComputeArmyScoreStandingRatioForNationPair(sourceNation, targetNation, swapRoles);
    } else {
      ratioScore = ComputeNavyScoreRatioForNationPair(sourceNation, targetNation, swapRoles);
      standingScore =
          ComputeNavyScoreStandingRatioForNationPair(sourceNation, targetNation, swapRoles);
    }
    float combinedScore = standingScore + ratioScore;
    if (GetWarNumber() <= combinedScore) {
      if (swapRoles == 0) {
        DeclareWarOn(sourceNation, 2, targetNation);
        return 1;
      }
      DeclareWarOn(targetNation, 2, sourceNation);
      return 1;
    }
    if (swapRoles == 0) {
      g_pDiplomacyTurnStateManager->TerminateAlliance(nationSlot, targetNation, 1);
    } else {
      g_pDiplomacyTurnStateManager->TerminateAlliance(nationSlot, sourceNation, 0);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e8040
bool TAutoGreatPower::PassesDiplomacyStrengthThresholdForTarget(int targetNation) {
  if (g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(targetNation, nationSlot)) {
    return false;
  }
  float allyNavyAccum = 0.0f;
  float allyArmyAccum = 0.0f;
  float armyScore = GetMilitaryPower();
  float navyScore = GetTotalNavalForce();
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->GetNumAllies(nationSlot) > 0) {
    do {
      int allyNation = g_pDiplomacyTurnStateManager->GetAllyNumber(allyIndex, nationSlot);
      allyArmyAccum = g_apNationStates[allyNation]->GetMilitaryPower() + allyArmyAccum;
      allyNavyAccum = g_apNationStates[allyNation]->GetTotalNavalForce() + allyNavyAccum;
      ++allyIndex;
    } while (allyIndex < g_pDiplomacyTurnStateManager->GetNumAllies(nationSlot));
  }
  int ownNavyInt = navyScore;
  int ownStrength = armyScore;
  if (ownStrength <= ownNavyInt) {
    ownStrength = ownNavyInt;
  }
  float ownStrengthScore = static_cast<float>(ownStrength);
  int allyNavyInt = allyNavyAccum;
  int allyStrength = allyArmyAccum;
  if (allyStrength <= allyNavyInt) {
    allyStrength = allyNavyInt;
  }
  float allyQuarterScore = static_cast<float>(allyStrength / 4);
  float strongestPeer = 0.0f;
  for (int peerSlot = 0; peerSlot < 7; ++peerSlot) {
    TGreatPower* peer = g_apNationStates[peerSlot];
    if (g_pSimMgr->ReallyInTheGame(peerSlot)) {
      float peerArmy = peer->GetMilitaryPower();
      if (strongestPeer < peerArmy) {
        strongestPeer = peerArmy;
      }
      float peerNavy = peer->GetTotalNavalForce();
      if (strongestPeer < peerNavy) {
        strongestPeer = peerNavy;
      }
    }
  }
  int tickQuarter = static_cast<short>(g_pSimMgr->economicTurn / 4);
  if (tickQuarter >= 0x3c) {
    tickQuarter = 0x3c;
  }
  short relationScore =
      g_pDiplomacyTurnStateManager->relationStandingScores[nationSlot * kNationSlotCount +
                                                           static_cast<short>(targetNation)];
  float combinedStrength = ownStrengthScore + allyQuarterScore;
  float combinedScore = static_cast<float>(
      (strongestPeer / combinedStrength +
       (static_cast<float>(relationScore) + ownStrengthScore) /
           ((static_cast<float>(tickQuarter) + combinedStrength) - g_Compute_Advisory_Map_Value)) *
      g_Evaluate_Advisory_Case11_Value);
  return GetAcceptAllianceNumber() <= combinedScore;
}

// FUNCTION: IMPERIALISM 0x004e8300
void TAutoGreatPower::SetConquerLust(int nationSlot, char makeEnemy) {
  if (g_apTerrainTypeDescriptorTable[nationSlot] == 0 ||
      g_apTerrainTypeDescriptorTable[nationSlot]->ownedRegionList->GetSize() <= 0) {
    return;
  }

  if (makeEnemy != 0) {
    bool isMinorNation = false;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0) {
      short encoded = g_apTerrainTypeDescriptorTable[nationSlot]->encodedNationSlot;
      if (encoded >= 100 && encoded <= 199) {
        isMinorNation = true;
      }
    }
    if (!isMinorNation) {
      zoneStatus[g_pActiveMapOrderContext->GetPortZone(static_cast<short>(nationSlot))
                     ->GetContextOrdinalOrInvalid()] = kMissionDesirabilityCandidate;
      return;
    }
    return;
  }

  zoneStatus[g_pActiveMapOrderContext->GetPortZone(static_cast<short>(nationSlot))
                 ->GetContextOrdinalOrInvalid()] = kMissionDesirabilityUnmarked;
}

// FUNCTION: IMPERIALISM 0x004e83d0
void TAutoGreatPower::CreateInitialMissions() {
  TLongintList* regionList = ownedRegionList;
  for (int i = 1; i <= regionList->GetSize(); i++) {
    int regionId = regionList->At(i);
    bool unavailable = g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
        regionId, nationSlot);
    provinceStatus[regionId] =
        unavailable ? kMissionDesirabilityUnmarked : kMissionDesirabilityCandidate;
    CreateMission(kMissionTypeDefendProvince, regionId, 0, -1);
  }

  TZone* portZone = g_pActiveMapOrderContext->GetPortZone(nationSlot);

  TZone* firstEntry = portZone->primaryNeighbors[0];

  short index = firstEntry->GetContextOrdinalOrInvalid();
  zoneStatus[index] = kMissionDesirabilityCandidate;
  CreateMission(kMissionTypeDefendProvince, -1, firstEntry, -1);

  index = portZone->GetContextOrdinalOrInvalid();
  zoneStatus[index] = kMissionDesirabilityCandidate;
  CreateMission(kMissionTypeDefendProvince, -1, portZone, -1);

  CreateMission(kMissionTypeScatteredShips, -1, 0, -1);
}

// FUNCTION: IMPERIALISM 0x004e8540
void TAutoGreatPower::CreateMission(eMissionType missionType, int mapNodeIndex, TZone* zoneContext,
                                    int relatedMapNodeIndex) {

  if (mapNodeIndex != -1 && provinceStatus[mapNodeIndex] != kMissionDesirabilityCandidate) {
    return;
  }

  if ((zoneContext != 0) && (relatedMapNodeIndex == -1)) {
    short index = zoneContext->GetContextOrdinalOrInvalid();
    if (zoneStatus[index] != kMissionDesirabilityCandidate) {
      return;
    }
  }

  eMissionType missionKind = missionType;
  if ((zoneContext != 0) && (mapNodeIndex == -1) && (relatedMapNodeIndex == -1) &&
      (missionType != kMissionTypeBlockadePort)) {
    missionKind = kMissionTypeDefendProvince;
  }

  TMission* missionObj = TMission::CreateMission(nationSlot, missionKind, mapNodeIndex, zoneContext,
                                                 relatedMapNodeIndex);
  if (missionObj == 0) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCountryAuto.cpp", 0x5ed);
  }

  TSortedList* missionQueue = this->missionQueue;
  missionQueue->AddTail(missionObj);

  if (mapNodeIndex != -1) {
    provinceStatus[mapNodeIndex] = kMissionDesirabilityQueued;
  }
  if ((zoneContext != 0) && (relatedMapNodeIndex == -1)) {
    short index = zoneContext->GetContextOrdinalOrInvalid();
    zoneStatus[index] = kMissionDesirabilityQueued;
  }
  if (relatedMapNodeIndex != -1) {
    provinceStatus[relatedMapNodeIndex] = kMissionDesirabilityQueued;
  }
}

// FUNCTION: IMPERIALISM 0x004e8680
void TAutoGreatPower::RemoveMission(eMissionType missionType, int key, TZone* zoneContext) {
  CIterator iter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
       mission = static_cast<TMission*>(iter.Advance())) {
    if (mission->Matches(missionType, key, zoneContext)) {
      CPtrList* list = &missionQueue->listState;
      POSITION position = list->Find(mission, 0);
      if (position != 0) {
        list->RemoveAt(position);
      }
      mission->Free();
      return;
    }
  }
}
// FUNCTION: IMPERIALISM 0x004e8b50
void TAutoGreatPower::SetProvinceStatus(int provinceIndex, eMissionDesirability value) {
  if (value == kMissionDesirabilityCandidate &&
      g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(provinceIndex,
                                                                              nationSlot)) {
    value = kMissionDesirabilityUnmarked;
  }
  provinceStatus[provinceIndex] = static_cast<unsigned char>(value);
}

// FUNCTION: IMPERIALISM 0x004e8ba0
void TAutoGreatPower::SetProvinceStatus(int provinceIndex, eMissionDesirability status,
                                        unsigned char bypassGate) {
  if (status == kMissionDesirabilityCandidate && bypassGate == 0 &&
      g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(provinceIndex,
                                                                              nationSlot)) {
    status = kMissionDesirabilityUnmarked;
  }
  provinceStatus[provinceIndex] = static_cast<unsigned char>(status);
}

// FUNCTION: IMPERIALISM 0x004e8bf0
void TAutoGreatPower::SetZoneStatus(int contextOrdinal, eMissionDesirability value) {
  zoneStatus[contextOrdinal] = static_cast<unsigned char>(value);
}

// FUNCTION: IMPERIALISM 0x004e92b0
void TAutoGreatPower::MarkEnemyProvinceCandidates() {
  int orderTypes[4];
  orderTypes[0] = 2;
  orderTypes[1] = 3;
  orderTypes[2] = 4;
  orderTypes[3] = 6;

  // Reset the transient (value 1) candidate flags; sticky values survive.
  int i;
  for (i = 0; i < kProvinceCount; ++i) {
    if (provinceStatus[i] == kMissionDesirabilityCandidate) {
      provinceStatus[i] = kMissionDesirabilityUnmarked;
    }
  }

  int slot;
  for (slot = 0; slot < 7; ++slot) {
    if (g_apNationStates[slot] != 0 && enemyFlags[slot] != 0) {
      int j;
      for (j = 1; j <= g_apNationStates[slot]->ownedRegionList->GetSize(); ++j) {
        int region = g_apNationStates[slot]->ownedRegionList->At(j);
        if (provinceStatus[region] == kMissionDesirabilityUnmarked) {
          eMissionDesirability markValue = kMissionDesirabilityCandidate;
          if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(region,
                                                                                      nationSlot)) {
            markValue = kMissionDesirabilityUnmarked;
          }
          provinceStatus[region] = markValue;
        }
      }
      if (g_pSimMgr->ReallyInTheGame(slot)) {
        int minorIndex;
        for (minorIndex = 0; minorIndex < 9; ++minorIndex) {
          TCountry* minorDescriptor = g_apTerrainTypeDescriptorTable[7 + minorIndex];
          if (minorDescriptor->IsColonyOf(slot)) {
            int m;
            for (m = 1; m <= minorDescriptor->ownedRegionList->GetSize(); ++m) {
              int minorRegion = minorDescriptor->ownedRegionList->At(m);
              if (provinceStatus[minorRegion] == kMissionDesirabilityUnmarked) {
                eMissionDesirability markValue = kMissionDesirabilityCandidate;
                if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                        minorRegion, nationSlot)) {
                  markValue = kMissionDesirabilityUnmarked;
                }
                provinceStatus[minorRegion] = markValue;
              }
            }
          }
        }
      }
    }
  }

  // Same marking for every flagged minor's own regions.
  int minorSlot;
  for (minorSlot = 0; minorSlot < kMinorNationCount; ++minorSlot) {
    if (enemyFlags[7 + minorSlot] != 0) {
      int j;
      for (j = 1; j <= g_apSecondaryNationStateSlots[7 + minorSlot]->ownedRegionList->GetSize();
           ++j) {
        int region = g_apSecondaryNationStateSlots[7 + minorSlot]->ownedRegionList->At(j);
        if (provinceStatus[region] == kMissionDesirabilityUnmarked) {
          eMissionDesirability markValue = kMissionDesirabilityCandidate;
          if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(region,
                                                                                      nationSlot)) {
            markValue = kMissionDesirabilityUnmarked;
          }
          provinceStatus[region] = markValue;
        }
      }
    }
  }

  if (g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(nationSlot)) {
    // At war: purge the interior minister's queues for each advisory order type.
    int t;
    for (t = 0; t < 4; ++t) {
      interiorMinister->ResetHistoricalNeedFor(orderTypes[t]);
    }
    return;
  }

  CString nationText;
  CString turnText;
  CString preludeText;
  FormatOverlayTerrainLabelText(&nationText);
  turnText.Format(g_szDecimalFormat, static_cast<short>(g_pSimMgr->economicTurn / 4));

  int t;
  for (t = 0; t < 4; ++t) {
    g_pSimMgr->GetCommodityName(static_cast<short>(orderTypes[t]), &preludeText);
    if (interiorMinister->GetHistoricalNeedFor(orderTypes[t]) >= 5) {
      TProvinceDesirabilityList* candidates = new TProvinceDesirabilityList();
      candidates->IProvinceDesirabilityList();

      int rec;
      for (rec = 0; rec < kProvinceCount; ++rec) {
        short owner = g_pGlobalMapState->cityScoreTable[rec].ownerNationCode;
        if (owner == -1) {
          continue;
        }
        if (g_pDiplomacyTurnStateManager->GetTreatyStatus(nationSlot, owner) ==
            kDiplomacyRelationshipAlliance) {
          continue;
        }
        if (g_apTerrainTypeDescriptorTable[owner]->encodedNationSlot >= 200) {
          if (g_pDiplomacyTurnStateManager->GetTreatyStatus(
                  nationSlot, g_apTerrainTypeDescriptorTable[owner]->DecodeOwnerNationSlot()) ==
              kDiplomacyRelationshipAlliance) {
            continue;
          }
        }
        if (provinceStatus[rec] != kMissionDesirabilityUnmarked) {
          continue;
        }
        if (((1 << orderTypes[t]) & g_pGlobalMapState->cityScoreTable[rec].resourcePresenceMask) ==
            0) {
          continue;
        }

        short score = g_pDiplomacyTurnStateManager
                          ->relationStandingScores[nationSlot * kNationSlotCount + owner];
        int linkBonus;
        int nodeBuffer[12];
        if (g_pGlobalMapState->HasDirectOrFallbackLinkedNodeType(rec, nationSlot, true)) {
          linkBonus = 0;
        } else if (g_pGlobalMapState->CollectSecondDegreeLinksWithMinorNationFallback(
                       rec, nationSlot, nodeBuffer, true) != 0) {
          linkBonus = 0x14;
        } else if (g_pActiveMapOrderContext->GetSeaZoneAdjacentTo(rec) != 0) {
          linkBonus = 0x28;
        } else {
          continue;
        }
        score += linkBonus;

        struct ProvinceCandidateRecord {
          short regionIndex;
          short score;
        } candidate;
        candidate.regionIndex = static_cast<short>(rec);
        candidate.score = score;
        if (owner < 7 && g_pSimMgr->ReallyInTheGame(owner)) {
          candidate.score = static_cast<short>(candidate.score + 0x14);
        }
        candidates->Insert(&candidate);
      }

      // Flag the top one or two candidates.
      if (candidates->GetSize() != 0) {
        short* topRecord = static_cast<short*>(candidates->GetPtrListEntryByOneBasedIndex(1));
        int topRegion = topRecord[0];
        if (provinceStatus[topRegion] == kMissionDesirabilityUnmarked) {
          eMissionDesirability markValue = kMissionDesirabilityCandidate;
          if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(topRegion,
                                                                                      nationSlot)) {
            markValue = kMissionDesirabilityUnmarked;
          }
          provinceStatus[topRegion] = markValue;
        }
        if (candidates->GetSize() >= 2) {
          short* secondRecord = static_cast<short*>(candidates->GetPtrListEntryByOneBasedIndex(2));
          int secondRegion = secondRecord[0];
          if (provinceStatus[secondRegion] == kMissionDesirabilityUnmarked) {
            eMissionDesirability markValue = kMissionDesirabilityCandidate;
            if (g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(
                    secondRegion, nationSlot)) {
              markValue = kMissionDesirabilityUnmarked;
            }
            provinceStatus[secondRegion] = markValue;
          }
        }
      }
      if (candidates != 0) {
        candidates->FreeList();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e9a50
void TAutoGreatPower::SelectAndQueueAdvisoryMapMissions(void) {
  bool hasActiveMission;
  bool queueSecondaryDefend;
  float bestScore;
  int bestRegion;
  float bestDirectScore;
  int bestTier;
  int directRegion;
  float secondBestDirectScore;
  TZone* bestPortZone;
  int bestLinkRegion;
  int secondBestDirectRegion;

  bestTier = -1;
  bestPortZone = 0;
  bestLinkRegion = -1;
  hasActiveMission = false;
  bestDirectScore = 0.0f;
  directRegion = -1;
  queueSecondaryDefend = false;
  if (city == 0) {
    return;
  }
  bestScore = 0.0f;
  bestRegion = -1;
  secondBestDirectScore = 0.0f;
  secondBestDirectRegion = -1;

  MarkEnemyProvinceCandidates();

  int region;
  for (region = 0; region < kProvinceCount; ++region) {
    unsigned char nodeFlag = provinceStatus[region];
    int linkRegion = -1;
    if (nodeFlag != kMissionDesirabilityCandidate) {
      continue;
    }
    float score;
    int tier;
    int nodeBuffer[12];
    if (g_pGlobalMapState->HasDirectOrFallbackLinkedNodeType(region, nationSlot, true)) {
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 0, -1);
      bestDirectScore = score;
      tier = 0;
      directRegion = region;
    } else if (g_pGlobalMapState->CollectSecondDegreeLinksWithMinorNationFallback(
                   region, nationSlot, nodeBuffer, true) != 0) {
      linkRegion = nodeBuffer[0];
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 1, linkRegion);
      tier = 1;
    } else if (g_pActiveMapOrderContext->GetSeaZoneAdjacentTo(region) != 0) {
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 2, -1);
      tier = 2;
    } else {
      score = g_Compute_Advisory_Zero;
      provinceStatus[region] = kMissionDesirabilityUnmarked;
    }
    if (score > bestScore) {
      bestScore = score;
      bestRegion = region;
      bestLinkRegion = linkRegion;
      bestTier = tier;
    }
    if (bestDirectScore > secondBestDirectScore && directRegion != -1) {
      secondBestDirectRegion = directRegion;
      secondBestDirectScore = bestDirectScore;
    }
  }

  // Port-zone contexts flagged available (state 1) compete with the region winner.
  TZone* zone;
  for (zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    if (zoneStatus[zone->GetContextOrdinalOrInvalid()] == kMissionDesirabilityCandidate) {
      float zoneScore = ComputeMapActionContextCompositeScoreForNation(zone);
      if (zoneScore > bestScore) {
        bestPortZone = zone;
        zone->GetContextOrdinalOrInvalid(); // dead call kept from the original
        bestScore = zoneScore;
        bestTier = zone->IsPortZone() ? 4 : 2;
      }
    }
  }

  int tier = bestTier;
  if (tier != -1) {
    bool acceptMission = false;
    if (g_afAdvisoryMissionTierThresholdByMinisterSkill[defenseMinister->skillIndex][tier] <
        bestScore) {
      acceptMission = true;
    } else if (g_pDiplomacyTurnStateManager->IsAtWarWithAnybody(nationSlot)) {
      CIterator missionIter(missionQueue);
      for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
           mission = static_cast<TMission*>(missionIter.Advance())) {
        if ((mission->marker11 & 1) != 0) {
          hasActiveMission = true;
          break;
        }
      }
      if (!hasActiveMission) {
        queueSecondaryDefend = true;
      }
    }
    if (acceptMission) {
      if (bestPortZone == 0) {
        if (tier == 2) {
          TZone* contextZone = g_pActiveMapOrderContext->GetSeaZoneAdjacentTo(bestRegion);
          if (contextZone != 0) {
            CreateMission(static_cast<eMissionType>(tier), -1, contextZone, bestRegion);
          } else {
            provinceStatus[bestRegion] = kMissionDesirabilityUnmarked;
          }
        } else if (bestLinkRegion != -1) {
          CreateMission(static_cast<eMissionType>(tier), bestLinkRegion, 0, bestRegion);
        } else {
          CreateMission(static_cast<eMissionType>(tier), bestRegion, 0, -1);
        }
      } else {
        CreateMission(static_cast<eMissionType>(tier), -1, bestPortZone, -1);
      }
    }
    if (queueSecondaryDefend && secondBestDirectRegion != -1) {
      CreateMission(kMissionTypeAttackProvince, secondBestDirectRegion, 0, -1);
    }
  }

  bool anyEligibleAtWar = false;
  int n;
  for (n = 0; n < 7 && !anyEligibleAtWar; ++n) {
    if (g_pDiplomacyTurnStateManager->AreAtWar(static_cast<short>(n), nationSlot) &&
        g_pSimMgr->ReallyInTheGame(static_cast<short>(n))) {
      anyEligibleAtWar = true;
    }
  }
  if (anyEligibleAtWar) {
    for (zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      short contextOrdinal = zone->GetContextOrdinalOrInvalid();
      if (zoneStatus[contextOrdinal] != kMissionDesirabilityQueued &&
          zone->IsAdjacentToCountry(nationSlot)) {
        for (n = 0; n < 7; ++n) {
          if (n != nationSlot &&
              g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, static_cast<short>(n)) &&
              (zone->nationKeyMask & static_cast<unsigned char>(1 << n)) != 0) {
            zoneStatus[contextOrdinal] = kMissionDesirabilityCandidate;
            CreateMission(kMissionTypeDefendProvince, -1, zone, -1);
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e9ed0
void TAutoGreatPower::DeclareWarOn(int targetNationSlot, int transitionMode, int sourceNationSlot) {
  SetEnemy(targetNationSlot);
  TGreatPower::DeclareWarOn(targetNationSlot, transitionMode, sourceNationSlot);
}

// FUNCTION: IMPERIALISM 0x004e9f10
bool TAutoGreatPower::HasEnemy(void) {
  bool anyActive = false;
  int candidate;
  for (candidate = 0; candidate < 7; ++candidate) {
    if (g_apNationStates[candidate] == 0) {
      enemyFlags[candidate] = 0;
    } else if (enemyFlags[candidate] != 0) {
      anyActive = true;
    }
  }
  TMinor** minorCursor = g_apNationAuxRuntimeStateSlots;
  do {
    if (enemyFlags[candidate] != 0) {
      if ((*minorCursor)->ownedRegionList->GetSize() == 0) {
        enemyFlags[candidate] = 0;
        if (g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, candidate)) {
          g_pDiplomacyTurnStateManager->SetNationPairDiplomacyRelationCodeFinal(
              nationSlot, candidate, kDiplomacyRelationshipPeace);
        }
      } else {
        anyActive = true;
      }
    }
    ++minorCursor;
    ++candidate;
  } while (minorCursor < g_apNationAuxRuntimeStateSlots + 16);
  return anyActive;
}

// FUNCTION: IMPERIALISM 0x004e9ff0
void TAutoGreatPower::SetEnemy(int targetNation) {
  if (HasEnemy()) {
    int nation = 0;
    TCountry** descriptorCursor = g_apTerrainTypeDescriptorTable;
    do {
      if (*descriptorCursor != 0 && nation != static_cast<short>(nationSlot)) {
        if (!g_pDiplomacyTurnStateManager->AreAtWar(nation, static_cast<short>(nationSlot))) {
          StopBeingEnemiesWith(nation);
        }
      }
      ++descriptorCursor;
      ++nation;
    } while (descriptorCursor < g_apTerrainTypeDescriptorTable + 0x17);
  }
  enemyFlags[targetNation] = 1;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetSize() > 0) {
      short ownerTag;
      if (g_apTerrainTypeDescriptorTable[targetNation] == 0 ||
          (ownerTag = g_apTerrainTypeDescriptorTable[targetNation]->encodedNationSlot,
           ownerTag < 100) ||
          199 < ownerTag) {
        TZone* portZone = g_pActiveMapOrderContext->GetPortZone(static_cast<short>(targetNation));
        short portZoneId = portZone->GetContextOrdinalOrInvalid();
        zoneStatus[portZoneId] = kMissionDesirabilityCandidate;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ea0e0
void TAutoGreatPower::StopBeingEnemiesWith(int targetNation) {
  enemyFlags[targetNation] = 0;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetSize() > 0) {
      TZone* portZone = g_pActiveMapOrderContext->GetPortZone(static_cast<short>(targetNation));
      short portZoneId = portZone->GetContextOrdinalOrInvalid();
      zoneStatus[portZoneId] = kMissionDesirabilityUnmarked;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ea150
void TAutoGreatPower::BecomeProtectorateOf(int targetNationSlot) {
  TGreatPower::BecomeProtectorateOf(targetNationSlot);

  int i = 0;
  for (i = 0; i < 6; ++i) {
    actionMetricByQuarter[i] = 0;
  }
  for (i = 0; i < kProvinceCount; ++i) {
    provinceStatus[i] = kMissionDesirabilityUnmarked;
  }
  for (i = 0; i < kPortZoneCount; ++i) {
    zoneStatus[i] = kMissionDesirabilityUnmarked;
  }
  KillMissions();
}

// FUNCTION: IMPERIALISM 0x004ea1c0
void TAutoGreatPower::LoseProvince(int regionId) {
  CIterator missionCursor(missionQueue);
  TMission* mission = static_cast<TMission*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    if (mission->Matches(kMissionTypeDefendProvince, regionId, NULL)) {
      CPtrList* listState = &missionQueue->listState;
      POSITION pos = listState->Find(mission, 0);
      if (pos != 0) {
        listState->RemoveAt(pos);
      }
      mission->Free();
      break;
    }
    mission = static_cast<TMission*>(missionCursor.Advance());
  }
  provinceStatus[regionId] = kMissionDesirabilityUnmarked;
  TGreatPower::LoseProvince(regionId);
}

// FUNCTION: IMPERIALISM 0x004ea290
void TAutoGreatPower::AddProvince(int regionId) {
  TGreatPower::AddProvince(regionId);
  provinceStatus[regionId] =
      g_pGlobalMapState->IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(regionId, nationSlot)
          ? kMissionDesirabilityUnmarked
          : kMissionDesirabilityCandidate;
  CreateMission(kMissionTypeDefendProvince, regionId, 0, -1);
}

// FUNCTION: IMPERIALISM 0x004ea300
void TAutoGreatPower::AddColony(int targetNation) {
  TGreatPower::AddColony(targetNation);
  int ordinal = 1;
  TLongintList* regionList = g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList;
  if (regionList->GetSize() > 0) {
    do {
      int regionId = regionList->At(ordinal);
      provinceStatus[regionId] = kMissionDesirabilityCandidate;
      CreateMission(kMissionTypeDefendProvince, regionId, 0, -1);
      ++ordinal;
    } while (ordinal <= regionList->GetSize());
  }
  TZone* portZone = g_pActiveMapOrderContext->GetPortZone(static_cast<short>(targetNation));
  TZone* firstOrder = portZone->primaryNeighbors[0];
  short portZoneId = firstOrder->GetContextOrdinalOrInvalid();
  zoneStatus[portZoneId] = kMissionDesirabilityCandidate;
  CreateMission(kMissionTypeDefendProvince, -1, firstOrder, -1);
}

// FUNCTION: IMPERIALISM 0x004ea430
void TAutoGreatPower::AnnounceLater(short orderKind, short payload, short flags) {}

// FUNCTION: IMPERIALISM 0x004ea450
void TAutoGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {}

// FUNCTION: IMPERIALISM 0x004ea470
void TAutoGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets();
  short carryValue = needCurrentByType[0x13];
  needCurrentByType[0x13] = 0;
  needCurrentByType[0x14] = static_cast<short>(needCurrentByType[0x14] + carryValue);
}

// FUNCTION: IMPERIALISM 0x004ea610
float TAutoGreatPower::ComputeAiIndustryActionCostFromSlot(short industrySlot) {
  int cost = g_pTradeMgr->GetPrice(0x0b) * g_industryActionCostWeightResCode0B[industrySlot];
  cost += g_pTradeMgr->GetPrice(0x08) * g_industryActionCostWeightResCode08[industrySlot];
  cost += g_pTradeMgr->GetPrice(0x09) * g_industryActionCostWeightResCode09[industrySlot];
  cost += g_pTradeMgr->GetPrice(0x0c) * g_industryActionCostWeightResCode0C[industrySlot];
  cost += g_pTradeMgr->GetPrice(0x10) * g_industryActionCostWeightResCode10[industrySlot];
  cost += g_pTradeMgr->GetPrice(0x03) * g_industryActionCostWeightResCode03[industrySlot];
  return static_cast<float>(cost);
}

// FUNCTION: IMPERIALISM 0x004ea700
float TAutoGreatPower::ComputeAiCityActionCostFromSlotAndMode(short actionSlot,
                                                              bool skipContextBias) {
  AiCityActionCostProfile& profile = g_aiCityActionCostProfiles[actionSlot];
  short capabilityLevel = needCurrentByType[5];
  float cost = static_cast<float>(profile.baseCost);

  if (profile.primaryMetricCode != -1 &&
      (profile.primaryMetricCode != 5 || capabilityLevel < profile.primaryMetricMultiplier)) {
    cost += static_cast<float>(g_pTradeMgr->GetPrice(profile.primaryMetricCode) *
                               profile.primaryMetricMultiplier);
  }
  if (profile.secondaryMetricCode != -1 &&
      (profile.secondaryMetricCode != 5 || capabilityLevel < profile.secondaryMetricMultiplier)) {
    cost += static_cast<float>(g_pTradeMgr->GetPrice(profile.secondaryMetricCode) *
                               profile.secondaryMetricMultiplier);
  }
  if (!skipContextBias) {
    cost += GetCachedAiCityActionContextBias(profile.contextBiasSelector);
  }
  return cost;
}

// FUNCTION: IMPERIALISM 0x004ea830
float TAutoGreatPower::GetCachedAiCityActionContextBias(short selector) {
  int cacheIndex;
  if (selector == 1) {
    cacheIndex = 0;
  } else if (selector == 2) {
    cacheIndex = 1;
  } else {
    cacheIndex = 2;
  }

  if (g_cachedAiCityActionTurnTick != g_pSimMgr->GetEconomicTurn()) {
    int base =
        g_pTradeMgr->GetPrice(0x0d) + g_pTradeMgr->GetPrice(0x0e) + g_pTradeMgr->GetPrice(0x07);
    int middle = g_pTradeMgr->GetPrice(0x0a) + 100;
    int tail = g_pTradeMgr->GetPrice(0x0a) * 2 + 1000;
    g_cachedAiCityActionContextBias[0] = static_cast<float>(base);
    g_cachedAiCityActionContextBias[1] = static_cast<float>(base + middle);
    g_cachedAiCityActionContextBias[2] = static_cast<float>(base + middle + tail);
    g_cachedAiCityActionNationSlot = nationSlot;
    g_cachedAiCityActionTurnTick = g_pSimMgr->GetEconomicTurn();
  }

  return g_cachedAiCityActionContextBias[cacheIndex];
}

// FUNCTION: IMPERIALISM 0x004ea990
void TAutoGreatPower::KillMissions() {
  bool removedMission;
  do {
    removedMission = false;
    CIterator iter(missionQueue);
    TMission* mission = static_cast<TMission*>(iter.Reset());
    CPtrList* list;
    if (iter.More() != 0) {
      list = &missionQueue->listState;
      POSITION position = list->Find(mission, 0);
      if (position != 0) {
        list->RemoveAt(position);
      }
      mission->Free();
      removedMission = true;
    }
  } while (removedMission);
}

// FUNCTION: IMPERIALISM 0x004eaa20
void TAutoGreatPower::RecomputeAiExpansionAndMissionPressureScores(void) {
  int totalRegionCount = 0;
  int compatibleRegionCount = 0;
  int activeMissionCount = 0;

  int regionOrdinal;
  for (regionOrdinal = 1; regionOrdinal <= ownedRegionList->GetSize(); ++regionOrdinal) {
    int regionId = ownedRegionList->At(regionOrdinal);
    if (IsMapTileCompatibleWithCurrentTerrainOrActionContext(regionId)) {
      ++compatibleRegionCount;
    }
    ++totalRegionCount;
  }

  TMinor** minorCursor = g_apNationAuxRuntimeStateSlots;
  do {
    if (*minorCursor != 0 && (*minorCursor)->IsColonyOf(nationSlot)) {
      for (regionOrdinal = 1; regionOrdinal <= (*minorCursor)->ownedRegionList->GetSize();
           ++regionOrdinal) {
        int regionId = (*minorCursor)->ownedRegionList->At(regionOrdinal);
        if (IsMapTileCompatibleWithCurrentTerrainOrActionContext(regionId)) {
          ++compatibleRegionCount;
        }
        ++totalRegionCount;
      }
    }
    ++minorCursor;
  } while (minorCursor < g_apNationAuxRuntimeStateSlots + 16);

  CIterator missionIterator(missionQueue);
  TMission* mission = static_cast<TMission*>(missionIterator.Reset());
  while (missionIterator.More()) {
    mission->AssertValid();
    if (mission->IsDefensiveSeaZoneMission()) {
      ++activeMissionCount;
    }
    mission = static_cast<TMission*>(missionIterator.Advance());
  }

  float ownUnitDivergence =
      g_afNationCombinedUnitDivergence[nationSlot] - g_afNationMobileUnitDivergence[nationSlot];
  averageUnitDivergencePerOwnedRegion = ownUnitDivergence / static_cast<float>(totalRegionCount);

  float maximumAdjustedMilitaryScore = 0.0f;
  float maximumAdjustedMissionScore = 0.0f;
  float maximumRawMilitaryScore = 0.0f;
  float minimumPeerCombinedDivergence = -1.0f;
  float minimumPeerOrderQueueDivergence = -1.0f;

  int peerNation;
  for (peerNation = 0; peerNation < kMajorNationCount; ++peerNation) {
    if (peerNation == nationSlot || g_apNationStates[peerNation] == 0) {
      continue;
    }

    float peerCombinedDivergence = g_afNationCombinedUnitDivergence[peerNation];
    if (peerCombinedDivergence < minimumPeerCombinedDivergence ||
        minimumPeerCombinedDivergence == g_AiPressureUnsetSentinel) {
      minimumPeerCombinedDivergence = peerCombinedDivergence;
    }

    float peerOrderQueueDivergence = g_afNationOrderQueueDivergence[peerNation];
    if (peerOrderQueueDivergence < minimumPeerOrderQueueDivergence ||
        minimumPeerOrderQueueDivergence == g_AiPressureUnsetSentinel) {
      minimumPeerOrderQueueDivergence = peerOrderQueueDivergence;
    }

    float militaryScore;
    if (g_pGlobalMapState->IsSameContinent(nationSlot, static_cast<short>(peerNation))) {
      militaryScore = g_afNationMobileUnitScore[peerNation];
    } else {
      militaryScore = g_afNationWeightedMilitaryOrderScore[peerNation];
    }

    if (militaryScore > maximumRawMilitaryScore) {
      maximumRawMilitaryScore = militaryScore;
    }

    float missionScore = g_afNationOrderQueueDivergenceMirror[peerNation];
    if (g_pDiplomacyTurnStateManager
            ->relationStandingScores[nationSlot * kNationSlotCount + peerNation] >= 100) {
      maximumAdjustedMilitaryScore = static_cast<float>(
          defenseMinister->GetStategicEscalationMultiplier(true) * militaryScore);
      missionScore = static_cast<float>(defenseMinister->GetStategicEscalationMultiplier(false) *
                                        missionScore);
    }

    if (militaryScore > maximumAdjustedMilitaryScore) {
      maximumAdjustedMilitaryScore = militaryScore;
    }
    if (missionScore > maximumAdjustedMissionScore) {
      maximumAdjustedMissionScore = missionScore;
    }
  }

  float militaryRatio = maximumRawMilitaryScore / (g_afNationMobileUnitDivergence[nationSlot] +
                                                   averageUnitDivergencePerOwnedRegion);
  if (militaryRatio > 1.0) {
    militaryRatio = g_AiPressureRatioCap;
  }

  float peerScaledMilitaryScore = (militaryRatio - g_AiPressureUnsetSentinel) *
                                  g_AiPressureMidpointScale * g_AiPressurePeerScale *
                                  minimumPeerCombinedDivergence;
  if (peerScaledMilitaryScore > maximumAdjustedMilitaryScore) {
    maximumAdjustedMilitaryScore = peerScaledMilitaryScore;
  }

  float expansionPressure = maximumAdjustedMilitaryScore - ownUnitDivergence;
  if (expansionPressure < g_MissionScoreZeroThreshold) {
    expansionPressure = 0.0f;
  }
  if (compatibleRegionCount != 0) {
    expansionPressure /= static_cast<float>(compatibleRegionCount);
  }
  expansionPressurePerCompatibleRegion = expansionPressure;

  if (activeMissionCount == 0) {
    activeMissionPressureAverage = maximumAdjustedMissionScore;
  } else {
    activeMissionPressureAverage =
        maximumAdjustedMissionScore / static_cast<float>(activeMissionCount);
  }
}

// FUNCTION: IMPERIALISM 0x004eae70
void TAutoGreatPower::ReassessMissions(int unused) {
  if (city == NULL) {
    return;
  }

  CIterator unitIter(militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    if (unit->ownerMission == NULL &&
        unit->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      TMission* mission =
          TMission::Find(missionQueue, kMissionTypeDefendProvince, unit->tileIndex, NULL);
      mission->AcceptReenforcement(unit, true);
    }
  }

  CIterator missionIter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
       mission = static_cast<TMission*>(missionIter.Advance())) {
    mission->Reassess();
  }

  TAutoGreatPower::ReplaceObsoleteMissions();
  UpdateTrackedEntryEligibilityByClassMaskAndRatio(0);
  AssignUnitsToMissions(0);
  PlanAiDevelopmentActionsFromResourcePools(0);
}

// FUNCTION: IMPERIALISM 0x004eafa0
void TAutoGreatPower::AssignMilitiaToDefendMissions() {
  CIterator iter(militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(iter.Reset()); iter.More();
       unit = static_cast<TMilitaryUnit*>(iter.Advance())) {
    if (unit->ownerMission == NULL &&
        unit->GetCategory() == EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      TMission* handler =
          TMission::Find(missionQueue, kMissionTypeDefendProvince, unit->tileIndex, NULL);
      handler->AcceptReenforcement(unit, true);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004eb040
void TAutoGreatPower::MReassess() {
  CIterator iter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
       mission = static_cast<TMission*>(iter.Advance())) {
    mission->Reassess();
  }
}

// FUNCTION: IMPERIALISM 0x004eb0d0
void TAutoGreatPower::ReplaceObsoleteMissions(void) {
  for (;;) {
    CIterator missionCursor(missionQueue);
    TMission* mission = static_cast<TMission*>(missionCursor.Reset());
    TMission* replacement;
    for (;;) {
      if (missionCursor.More() == 0) {
        return;
      }
      replacement = mission->GetReplacement();
      if (replacement != mission) {
        break;
      }
      mission = static_cast<TMission*>(missionCursor.Advance());
    }
    CPtrList* listState = &missionQueue->listState;
    POSITION pos = listState->Find(mission, 0);
    if (pos != 0) {
      listState->RemoveAt(pos);
    }
    mission->Free();
    if (replacement != 0) {
      missionQueue->AddTail(replacement);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004eb190
void TAutoGreatPower::PlanAiDevelopmentActionsFromResourcePools(int unused) {
  if (this == 0) {
    return;
  }
  if (city == 0) {
    return;
  }

  int resourcePools[9] = {0};
  TMilitaryUnit* bestUnitByType[30] = {0};

  CIterator unitIter(militaryUnitList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
    if (unit->CanUpgrade()) {
      int qualityLevel = unit->experiencePercent / 100;
      short unitType = unit->orderType;
      if (bestUnitByType[unitType] == 0 ||
          bestUnitByType[unitType]->experiencePercent / 100 < qualityLevel) {
        bestUnitByType[unitType] = unit;
      }
    }
  }

  CIterator missionIter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
       mission = static_cast<TMission*>(missionIter.Advance())) {
    mission->AssertValid();
    if (mission->flag10 == 0) {
      mission->AccumulateLack(resourcePools, true);
    }
  }

  interiorMinister->AssertValid();
  int averageAllocation = interiorMinister->GetAverageDevelopmentOrderAllocation();
  int cityActionLimit = averageAllocation + 2;
  int industryActionLimit = averageAllocation / 2 + 1;
  float developmentBudget = interiorMinister->GetAiDevelopmentResourceBudgetScale(resourcePools);
  int industryActionCount = 0;
  int cityActionCount = 0;

  for (int iteration = 0; iteration < 99; ++iteration) {
    int selectedSlot = -1;
    char selectedIsIndustry;
    char selectedIsUpgrade;
    float selectedWeightedCost;
    if (!SelectBestCityDevelopmentFromResourcePools(nationSlot, resourcePools, bestUnitByType,
                                                    &selectedIsIndustry, &selectedIsUpgrade,
                                                    &selectedSlot, 0, &selectedWeightedCost)) {
      return;
    }

    bool applyAction;
    if (selectedIsIndustry != 0) {
      applyAction = industryActionCount++ < industryActionLimit;
    } else {
      applyAction = cityActionCount++ < cityActionLimit;
    }
    if (industryActionCount > industryActionLimit && cityActionCount > cityActionLimit) {
      return;
    }

    if (selectedIsIndustry != 0) {
      if (applyAction) {
        interiorMinister->IndustryOrder(static_cast<short>(selectedSlot));
      }

      int actionCost =
          g_pTradeMgr->GetPrice(0x0b) * g_industryActionCostWeightResCode0B[selectedSlot];
      actionCost += g_pTradeMgr->GetPrice(0x08) * g_industryActionCostWeightResCode08[selectedSlot];
      actionCost += g_pTradeMgr->GetPrice(0x09) * g_industryActionCostWeightResCode09[selectedSlot];
      actionCost += g_pTradeMgr->GetPrice(0x10) * g_industryActionCostWeightResCode10[selectedSlot];
      actionCost += g_pTradeMgr->GetPrice(0x0c) * g_industryActionCostWeightResCode0C[selectedSlot];
      actionCost += g_pTradeMgr->GetPrice(0x03) * g_industryActionCostWeightResCode03[selectedSlot];
      developmentBudget -= static_cast<float>(actionCost);

      for (int resourceIndex = 0; resourceIndex < 4; ++resourceIndex) {
        resourcePools[5 + resourceIndex] -= GetNormalizedIndustryActionResourceCostPercent(
            resourceIndex, static_cast<short>(selectedSlot));
      }
    } else {
      if (applyAction) {
        interiorMinister->PleaseBuildLandUnit(static_cast<short>(selectedSlot));
      }
      developmentBudget -=
          ComputeAiCityActionCostFromSlotAndMode(static_cast<short>(selectedSlot), false);
      for (int resourceIndex = 0; resourceIndex < 5; ++resourceIndex) {
        resourcePools[resourceIndex] -= TMilitaryUnit::GetTypeAttribute(
            static_cast<short>(selectedSlot), static_cast<short>(resourceIndex));
      }
    }
  }
  // Retail stores and decrements this float but never consumes its value.
  (void)developmentBudget;
}

// FUNCTION: IMPERIALISM 0x004eb5d0
short CompareMissionsByWeightedShortfall(TMission* left, TMission* right) {
  left->AssertValid();
  right->AssertValid();
  if (left->state08 < right->state08) {
    return -1;
  }

  float leftShortfall = 1.0f - left->GetWeightedSatisfaction();
  if (0.0f <= leftShortfall) {
    leftShortfall = left->importanceScore * leftShortfall;
  } else {
    leftShortfall = leftShortfall / left->importanceScore;
  }

  float rightShortfall = 1.0f - right->GetWeightedSatisfaction();
  if (0.0f <= rightShortfall) {
    rightShortfall *= right->importanceScore;
  } else {
    rightShortfall = rightShortfall / right->importanceScore;
  }

  if (rightShortfall < leftShortfall) {
    return -1;
  }
  if (leftShortfall < rightShortfall) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004eb6b0
void TAutoGreatPower::UpdateTrackedEntryEligibilityByClassMaskAndRatio(int unused) {
  missionQueue->SortBy(&CompareMissionOrderEntriesByMovementClassThenEfficiency, this);

  TMission* nextByClass[4] = {NULL, NULL, NULL, NULL};
  int availableClassMask = 3;
  {
    CIterator candidateIter(missionQueue);
    for (TMission* mission = static_cast<TMission*>(candidateIter.Reset()); candidateIter.More();
         mission = static_cast<TMission*>(candidateIter.Advance())) {
      int classMask = static_cast<char>(mission->marker11);
      if (mission->flag10 == 0 && classMask != 0) {
        nextByClass[classMask] = mission;
      }
    }
  }

  CIterator missionIter(missionQueue);
  for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
       mission = static_cast<TMission*>(missionIter.Advance())) {
    int classMask = static_cast<char>(mission->marker11);
    if (nextByClass[classMask] == mission) {
      nextByClass[classMask] = NULL;
    }

    bool eligible =
        classMask == 0 || (classMask & availableClassMask) == classMask || mission->state08 == 0;
    if (eligible && (classMask & 1) != 0 && !mission->IsArmyMission()) {
      eligible = false;
    }
    if (eligible && classMask != 0) {
      TMission* nextMission = nextByClass[classMask];
      if (nextMission != NULL) {
        float nextMissionRatio =
            nextMission->importanceScore / nextMission->IndustrialCostOfNeeds();
        float missionRatio = mission->importanceScore / mission->IndustrialCostOfNeeds();
        if (missionRatio < nextMissionRatio * g_MissionEligibilityRatioMargin) {
          eligible = false;
        } else {
          availableClassMask &= ~classMask;
        }
      } else {
        availableClassMask &= ~classMask;
      }
    }
    mission->Hold(!eligible);
  }
}

namespace {

inline float ComputeMissionRemainingPriorityScore(TMission* mission) {
  float diff = 1.0 - mission->GetWeightedSatisfaction();
  return (diff >= 0.0f) ? diff * mission->importanceScore : diff / mission->importanceScore;
}

} // namespace

// FUNCTION: IMPERIALISM 0x004eb8b0
void TAutoGreatPower::AssignUnitsToMissions(int unused) {
  {
    CIterator resetIter(missionQueue);
    for (TMission* entry = static_cast<TMission*>(resetIter.Reset()); resetIter.More();
         entry = static_cast<TMission*>(resetIter.Advance())) {
      entry->SmokeEmIfYouGotEm();
    }
  }

  int weights[9];
  float weightFractions[9];
  int total;
  for (;;) {
    TMission* bestNavy = NULL;
    {
      CIterator navyIter(missionQueue);
      for (TMission* entry = static_cast<TMission*>(navyIter.Reset()); navyIter.More();
           entry = static_cast<TMission*>(navyIter.Advance())) {
        TMission* candidate = entry->GetNavyMission();
        if (candidate == NULL || candidate->flag10 != 0) {
          continue;
        }
        if (bestNavy == NULL) {
          bestNavy = candidate;
          continue;
        }
        float candidateScore = ComputeMissionRemainingPriorityScore(candidate);
        float bestScore = ComputeMissionRemainingPriorityScore(bestNavy);
        if (candidateScore > g_MissionScoreZeroThreshold &&
            static_cast<char>(candidate->state08) < static_cast<char>(bestNavy->state08)) {
          bestNavy = candidate;
          continue;
        }
        if (bestScore <= g_MissionScoreZeroThreshold ||
            static_cast<char>(candidate->state08) <= static_cast<char>(bestNavy->state08)) {
          float bestScore2 = ComputeMissionRemainingPriorityScore(bestNavy);
          float candidateScore2 = ComputeMissionRemainingPriorityScore(candidate);
          if (bestScore2 < candidateScore2) {
            bestNavy = candidate;
          }
        }
      }
    }

    if (bestNavy != NULL) {
      for (int navyZeroIdx = 0; navyZeroIdx < 9; ++navyZeroIdx) {
        weights[navyZeroIdx] = 0;
      }
      total = bestNavy->AccumulateLack(weights, false);
      for (int navyWeightIdx = 0; navyWeightIdx < 9; ++navyWeightIdx) {
        weightFractions[navyWeightIdx] =
            static_cast<float>(weights[navyWeightIdx]) / static_cast<float>(total);
      }

      TShip* bestShip = NULL;
      float bestShipScore = 0.0f;
      for (TShip* shipNode = TShip::GetFirst(); shipNode != NULL; shipNode = shipNode->next) {
        if (shipNode->nation == nationSlot && shipNode->mission == NULL) {
          float score = bestNavy->FitnessOf(shipNode, weightFractions);
          if (bestShip == NULL || bestShipScore < score) {
            bestShipScore = score;
            bestShip = shipNode;
          }
        }
      }

      if (bestShip != NULL) {
        bestNavy->AcceptReenforcement(bestShip, true);
        continue;
      }
    }

    TMission* bestArmy = NULL;
    TMission* eligibleRunnerUp = NULL;
    {
      CIterator armyIter(missionQueue);
      for (TMission* entry = static_cast<TMission*>(armyIter.Reset()); armyIter.More();
           entry = static_cast<TMission*>(armyIter.Advance())) {
        TMission* candidate = entry->GetArmyMission();
        if (candidate == NULL || candidate->flag10 != 0) {
          continue;
        }
        float candidateScore = ComputeMissionRemainingPriorityScore(candidate);
        if (eligibleRunnerUp == NULL && candidateScore > g_MissionScoreZeroThreshold &&
            (candidate->marker11 & 1) != 0) {
          eligibleRunnerUp = candidate;
        }
        if (bestArmy == NULL) {
          bestArmy = candidate;
          continue;
        }
        float bestArmyScore = ComputeMissionRemainingPriorityScore(bestArmy);
        if (candidateScore > g_MissionScoreZeroThreshold &&
            static_cast<char>(bestArmy->state08) > static_cast<char>(candidate->state08)) {
          bestArmy = candidate;
          continue;
        }
        if (bestArmyScore > g_MissionScoreZeroThreshold &&
            static_cast<char>(bestArmy->state08) < static_cast<char>(candidate->state08)) {
          continue;
        }
        if (bestArmyScore < candidateScore) {
          bestArmy = candidate;
        }
      }
    }

    if (bestArmy == NULL) {
      return;
    }
    if (eligibleRunnerUp != NULL &&
        static_cast<char>(eligibleRunnerUp->state08) <= static_cast<char>(bestArmy->state08) &&
        (bestArmy->marker11 & 1) == 0) {
      float bestArmyRatio = bestArmy->importanceScore / bestArmy->IndustrialCostOfNeeds();
      float runnerUpRatio =
          eligibleRunnerUp->importanceScore / eligibleRunnerUp->IndustrialCostOfNeeds();
      if (bestArmyRatio < runnerUpRatio) {
        bestArmy = eligibleRunnerUp;
      }
    }

    for (int armyZeroIdx = 0; armyZeroIdx < 9; ++armyZeroIdx) {
      weights[armyZeroIdx] = 0;
    }
    bestArmy->AccumulateLack(weights, false);
    total = 0;
    for (int armyClampIdx = 0; armyClampIdx < 9; ++armyClampIdx) {
      if (weights[armyClampIdx] < 0) {
        weights[armyClampIdx] = 0;
      }
      total += weights[armyClampIdx];
    }
    if (total == 0) {
      total = 1;
    }
    for (int armyNormIdx = 0; armyNormIdx < 9; ++armyNormIdx) {
      weightFractions[armyNormIdx] =
          static_cast<float>(weights[armyNormIdx]) / static_cast<float>(total);
    }

    TMilitaryUnit* bestUnit = NULL;
    float bestUnitScore = 0.0f;
    {
      CIterator unitIter(militaryUnitList);
      for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(unitIter.Reset()); unitIter.More();
           unit = static_cast<TMilitaryUnit*>(unitIter.Advance())) {
        if (unit->ownerMission == NULL) {
          float score = bestArmy->FitnessOf(unit, weightFractions);
          if (bestUnit == NULL || bestUnitScore < score) {
            bestUnitScore = score;
            bestUnit = unit;
          }
        }
      }
    }

    if (bestUnit == NULL) {
      return;
    }
    bestArmy->AcceptReenforcement(bestUnit, true);
  }
}

// FUNCTION: IMPERIALISM 0x00535b00
bool SelectBestCityDevelopmentFromResourcePools(int nationSlot, int* resourcePools,
                                                TMilitaryUnit** bestUnitByType,
                                                char* selectedIsIndustry, char* selectedIsUpgrade,
                                                int* selectedSlot, int unused,
                                                float* selectedWeightedCost) {
  *selectedSlot = -1;
  int resourceIndex = 0;
  while (resourceIndex < 9 && resourcePools[resourceIndex] <= 0) {
    ++resourceIndex;
  }
  if (resourceIndex >= 9) {
    return false;
  }

  float bestScore = 0.0f;
  for (short actionSlot = 0; actionSlot < 30; ++actionSlot) {
    if (g_pTechMgr->abilityActiveRows[nationSlot].abilityActiveById[actionSlot] == 0) {
      continue;
    }
    if (TMilitaryUnit::GetTypeCategory(actionSlot) ==
            EncodeArmyUnitCategory(kArmyUnitCategoryMilitia) ||
        TMilitaryUnit::GetTypeCategory(actionSlot) ==
            EncodeArmyUnitCategory(kArmyUnitCategoryGeneral)) {
      continue;
    }

    float weightedCost = 0.0f;
    for (short poolIndex = 0; poolIndex < 5; ++poolIndex) {
      if (resourcePools[poolIndex] > 0) {
        weightedCost += static_cast<float>(TMilitaryUnit::GetTypeAttribute(actionSlot, poolIndex) *
                                           resourcePools[poolIndex]);
      }
    }
    float score = weightedCost / static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot])
                                     ->ComputeAiCityActionCostFromSlotAndMode(actionSlot, false);
    if (score > bestScore) {
      bestScore = score;
      *selectedSlot = actionSlot;
      *selectedIsIndustry = 0;
      *selectedIsUpgrade = 0;
      if (selectedWeightedCost != 0) {
        *selectedWeightedCost = weightedCost;
      }
    }
  }

  for (short unitType = 0; unitType < 30; ++unitType) {
    if (TMilitaryUnit::GetTypeCategory(unitType) ==
            EncodeArmyUnitCategory(kArmyUnitCategoryMilitia) ||
        TMilitaryUnit::GetTypeCategory(unitType) ==
            EncodeArmyUnitCategory(kArmyUnitCategoryGeneral) ||
        bestUnitByType[unitType] == 0) {
      continue;
    }

    short upgradeSlot = bestUnitByType[unitType]->UpgradeType();
    float weightedCost = 0.0f;
    for (short poolIndex = 0; poolIndex < 5; ++poolIndex) {
      if (resourcePools[poolIndex] > 0) {
        int costDelta = TMilitaryUnit::GetTypeAttribute(upgradeSlot, poolIndex) -
                        TMilitaryUnit::GetTypeAttribute(unitType, poolIndex);
        weightedCost += static_cast<float>(costDelta * resourcePools[poolIndex]);
      }
    }
    int qualityMultiplier = (bestUnitByType[unitType]->experiencePercent / 100 + 10) / 10;
    weightedCost *= static_cast<float>(qualityMultiplier);
    float score = weightedCost / static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot])
                                     ->ComputeAiCityActionCostFromSlotAndMode(upgradeSlot, true);
    if (score > bestScore) {
      bestScore = score;
      *selectedSlot = upgradeSlot;
      *selectedIsIndustry = 0;
      *selectedIsUpgrade = 1;
      if (selectedWeightedCost != 0) {
        *selectedWeightedCost = weightedCost;
      }
    }
  }

  for (short industryClass = 0; industryClass < 4; ++industryClass) {
    short industrySlot = GetEnabledIndustryCapabilitySlotByClass(industryClass);
    if (industrySlot <= 0) {
      continue;
    }

    float weightedCost = 0.0f;
    for (int poolIndex = 0; poolIndex < 4; ++poolIndex) {
      if (resourcePools[5 + poolIndex] > 0) {
        weightedCost += static_cast<float>(
            GetNormalizedIndustryActionResourceCostPercent(poolIndex, industrySlot) *
            resourcePools[5 + poolIndex]);
      }
    }
    float score = weightedCost / static_cast<TAutoGreatPower*>(g_apNationStates[nationSlot])
                                     ->ComputeAiIndustryActionCostFromSlot(industrySlot);
    if (score > bestScore) {
      bestScore = score;
      *selectedSlot = industrySlot;
      *selectedIsIndustry = 1;
      *selectedIsUpgrade = 0;
      if (selectedWeightedCost != 0) {
        *selectedWeightedCost = weightedCost;
      }
    }
  }

  if (*selectedSlot < 0) {
    return false;
  }

  if (*selectedIsIndustry != 0) {
    for (int poolIndex = 0; poolIndex < 4; ++poolIndex) {
      resourcePools[5 + poolIndex] -= GetNormalizedIndustryActionResourceCostPercent(
          poolIndex, static_cast<short>(*selectedSlot));
    }
  } else {
    for (short poolIndex = 0; poolIndex < 5; ++poolIndex) {
      resourcePools[poolIndex] -=
          TMilitaryUnit::GetTypeAttribute(static_cast<short>(*selectedSlot), poolIndex);
    }
  }
  return true;
}
