#include "game/nation_domain_types.h"
#include "game/diplomacy_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/nation/TForeignMinister.h"

#include "game/ui_widgets/TTradeMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/military_ui/TSortedByRelationshipList.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/city_ui/TLongintList.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/map/TIndexAndRankList.h"
#include "game/nation/TMinor.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/mfc.h"
#include "game/core/TStream.h"
#include "game/nation_stream_serialization.h"

#include <stdlib.h>

static const short kNoInteriorBidResource = -10;

namespace {

struct MinisterPriorityEntry {
  short resourceCode;
  short priority;
  short rank;
};

static int SelectDevelopmentGrantAmount(int availableBudget) {
  if (availableBudget < 3000) {
    return 1000;
  }
  if (availableBudget < 5000) {
    return 3000;
  }
  return availableBudget < 10000 ? 5000 : 10000;
}

} // namespace

IMPLEMENT_DYNCREATE(TForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x0052f070
TForeignMinister::TForeignMinister() : TMinister() {
  memset(tradePartnerEnabled, 1, sizeof(tradePartnerEnabled));
  memset(developmentGrantByNation, 0, sizeof(developmentGrantByNation));
  specialOfferQuota = 0;
  field48 = 0;
  tradeBidRefreshInterval = 5;
  interiorOrderKind = 2;
}

// FUNCTION: IMPERIALISM 0x0052f130
void TForeignMinister::IForeignMinister(TGreatPower* owner) {
  IMinister(owner);
  interiorBidResource = kNoInteriorBidResource;
  interiorBidAmount = 0;
  priceCheckPending = 0;
  diplomacyPhaseCounter = 0;
  memset(purchasePriorityByResource, 0, sizeof(purchasePriorityByResource));
  for (int i = 0; i < 4; ++i) {
    preferredResourceSlots[i] = kNoInteriorBidResource;
  }
}

// FUNCTION: IMPERIALISM 0x0052f180
void TForeignMinister::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&skillIndex, 2);
  stream->ReadBytes(&interiorBidResource, 2);
  stream->ReadBytes(&interiorBidAmount, 2);
  stream->ReadBytes(&priceCheckPending, 2);
  stream->ReadBytes(&specialOfferQuota, 2);
  stream->ReadBytes(&diplomacyPhaseCounter, 2);
  stream->ReadBytes(&tradeBidRefreshInterval, 2);
  stream->ReadBytes(&interiorOrderKind, 2);
  stream->ReadBytes(purchasePriorityByResource, sizeof(purchasePriorityByResource));
  SwapShortArrayBytes(purchasePriorityByResource, 0x11);
  stream->ReadBytes(preferredResourceSlots, sizeof(preferredResourceSlots));
  SwapShortArrayBytes(preferredResourceSlots, 4);
  stream->ReadBytes(&field48, 1);
  stream->ReadBytes(tradePartnerEnabled, sizeof(tradePartnerEnabled));
  if (g_nSaveFormatVersion >= 0x15) {
    stream->ReadBytes(developmentGrantByNation, sizeof(developmentGrantByNation));
    SwapShortArrayBytes(developmentGrantByNation, 0x17);
  }
}

// FUNCTION: IMPERIALISM 0x0052f2b0
void TForeignMinister::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&skillIndex, 2);
  stream->WriteBytes(&interiorBidResource, 2);
  stream->WriteBytes(&interiorBidAmount, 2);
  stream->WriteBytes(&priceCheckPending, 2);
  stream->WriteBytes(&specialOfferQuota, 2);
  stream->WriteBytes(&diplomacyPhaseCounter, 2);
  stream->WriteBytes(&tradeBidRefreshInterval, 2);
  stream->WriteBytes(&interiorOrderKind, 2);
  WriteShortArrayElems(stream, purchasePriorityByResource, 0x11);
  WriteShortArrayElems(stream, preferredResourceSlots, 4);
  stream->WriteBytes(&field48, 1);
  stream->WriteBytes(tradePartnerEnabled, sizeof(tradePartnerEnabled));
  WriteShortArrayElems(stream, developmentGrantByNation, 0x17);
}

// FUNCTION: IMPERIALISM 0x0052f430
short TForeignMinister::GetRankingCriterionForGP(short nationSlot) {
  short relationTotal = 0;
  for (short otherNation = 0; otherNation < kNationSlotCount; ++otherNation) {
    if (otherNation != nationSlot && g_apTerrainTypeDescriptorTable[otherNation] != 0) {
      relationTotal = static_cast<short>(
          relationTotal +
          g_pDiplomacyTurnStateManager
              ->relationStandingScores[nationSlot * kNationSlotCount + otherNation]);
    }
  }
  return relationTotal / (g_pSimMgr->GetNumCountries() - 1);
}

// FUNCTION: IMPERIALISM 0x0052f4b0
void TForeignMinister::InitializeTradeStatus() {
  memset(tradePartnerEnabled, 1, 7);
  TGreatPower* ownerGP = greatPower;
  specialOfferQuota = 0;
  if (ownerGP->treasuryValue < 0) {
    priceCheckPending = 1;
  }
}

// FUNCTION: IMPERIALISM 0x0052f4f0
void TForeignMinister::PleaseBuy(short index, short delta) {
  purchasePriorityByResource[index] = static_cast<short>(purchasePriorityByResource[index] + delta);
}

// FUNCTION: IMPERIALISM 0x0052f520
void TForeignMinister::PriceCheck() {
  priceCheckPending = 1;
}

// FUNCTION: IMPERIALISM 0x0052f540
void TForeignMinister::SetInteriorMinisterBid(short primary, short secondary) {
  interiorBidResource = primary;
  interiorBidAmount = secondary;
}

// FUNCTION: IMPERIALISM 0x0052f570
void TForeignMinister::SetBuyPriorities() {
  TIndexAndRankList* priorities = new TIndexAndRankList();
  priorities->recordSize = sizeof(MinisterPriorityEntry);

  for (short resourceCode = 0; resourceCode < kResourceManufacturedEnd; ++resourceCode) {
    if (purchasePriorityByResource[resourceCode] != 0) {
      MinisterPriorityEntry entry;
      entry.resourceCode = resourceCode;
      entry.priority = static_cast<short>(purchasePriorityByResource[resourceCode] + 1);
      priorities->Insert(&entry);
    }
  }

  for (int preferenceIndex = 0; preferenceIndex < 4; ++preferenceIndex) {
    bool alreadyPresent = false;
    for (short entryIndex = 1; entryIndex <= priorities->GetSize() && !alreadyPresent;
         ++entryIndex) {
      MinisterPriorityEntry* entry = static_cast<MinisterPriorityEntry*>(
          priorities->GetPtrListEntryByOneBasedIndex(entryIndex));
      if (entry->resourceCode == preferredResourceSlots[preferenceIndex]) {
        alreadyPresent = true;
      }
    }
    if (!alreadyPresent) {
      MinisterPriorityEntry entry;
      entry.resourceCode = preferredResourceSlots[preferenceIndex];
      entry.priority = 1;
      priorities->Insert(&entry);
    }
  }

  for (int selectedIndex = 0; selectedIndex < 4; ++selectedIndex) {
    MinisterPriorityEntry* entry = static_cast<MinisterPriorityEntry*>(
        priorities->GetPtrListEntryByOneBasedIndex(selectedIndex + 1));
    preferredResourceSlots[selectedIndex] = entry->resourceCode;
  }
  priorities->FreeList();
}

// FUNCTION: IMPERIALISM 0x0052f730
int TForeignMinister::WeNeedMoney() {
  // The original reloads the owner (this->greatPower) once per comparison.
  TGreatPower* gp = greatPower;
  short cap = gp->merchantCapacity;
  if (gp->GetStockpile(kResourceClothing) < cap) {
    gp = greatPower;
    cap = gp->merchantCapacity;
    if (gp->GetStockpile(kResourceFurniture) < cap) {
      gp = greatPower;
      cap = gp->merchantCapacity;
      if (gp->GetStockpile(kResourceHardware) < cap) {
        return 0;
      }
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0052f7b0
void TForeignMinister::ArrangeMaterialsOffers() {
  TGreatPower* owner = greatPower;

  if (interiorBidResource != kNoInteriorBidResource) {
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->ISortedByRelationshipList();
    g_pDiplomacyTurnStateManager->BuildRelationshipList(owner->nationSlot, 1, relationshipList);
    short* nationSlotPtr = static_cast<short*>(
        relationshipList->GetPtrListEntryByOneBasedIndex(relationshipList->GetSize()));
    g_apNationStates[*nationSlotPtr]->SetTradeOffersFor(interiorBidResource, owner->nationSlot);
    if (relationshipList != 0) {
      relationshipList->FreeList();
    }
  }

  if (purchasePriorityByResource[5] > 0) {
    bool foundFallbackNation = false;
    int trialIndex = 1;
    int fallbackNationSlot = 0;
    do {
      if (foundFallbackNation) {
        break;
      }
      fallbackNationSlot = rand() % 7;
      if (g_pSimMgr->ReallyInTheGame(static_cast<short>(fallbackNationSlot))) {
        if (!g_pDiplomacyTurnStateManager->AreAtWar(fallbackNationSlot, owner->nationSlot) &&
            fallbackNationSlot != owner->nationSlot) {
          foundFallbackNation = true;
        }
      }
    } while (trialIndex++ < 0x14);
    if (foundFallbackNation) {
      g_apNationStates[fallbackNationSlot]->SetTradeOffersFor(5, owner->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052f940
void TForeignMinister::SetTradeBids() {
  InitializeTradeStatus();
  TGreatPower* owner = greatPower;
  int skipMissionSlot1A = 0;
  if (diplomacyPhaseCounter < tradeBidRefreshInterval) {
    if (WeNeedMoney() == 0) {
      skipMissionSlot1A = 1;
    }
  }
  if (skipMissionSlot1A == 0) {
    owner->interiorMinister->PleaseBuildShip(interiorOrderKind);
    diplomacyPhaseCounter = 0;
  }
  SetBuyPriorities();
  if (interiorBidResource != kNoInteriorBidResource) {
    short idx = interiorBidResource;
    purchasePriorityByResource[idx] = interiorBidAmount;
    owner->SetItemPotentials(idx, static_cast<short>(-1));
  }
}

// FUNCTION: IMPERIALISM 0x0052f9d0
void TForeignMinister::DoUsualSubsidyRule() {
  TGreatPower* owner = greatPower;
  short nationSlot = owner->nationSlot;
  const short kOrderKinds[] = {0, 1, 2, 3, 4, 5, 6};
  int loopCount = (g_pTechMgr->orderCapRows277[nationSlot].techStatusByTechId[0x13] == 2) + 5;
  if (loopCount != 0) {
    const short* orderKindCursor = kOrderKinds;
    do {
      int roll = rand();
      short orderKind = *orderKindCursor;
      short weightThreshold = g_pTradeMgr->GetPrice(orderKind);
      if (roll % 100 + 200 < static_cast<int>(weightThreshold)) {
        short metric = owner->GetStockpile(orderKind);
        if (metric == 0) {
          owner->SetItemPotentials(orderKind, 0);
        } else {
          int assignAmount = static_cast<int>(metric) / 2;
          if (assignAmount > 4) {
            assignAmount = 5;
          }
          owner->SetItemPotentials(orderKind, static_cast<short>(assignAmount));
        }
      }
      ++orderKindCursor;
      --loopCount;
    } while (loopCount != 0);
  }

  int roll = rand();
  short tradeWeight = g_pTradeMgr->GetPrice(5);
  if (roll % 100 + 200 < static_cast<int>(tradeWeight)) {
    short tradeMetric = owner->GetStockpile(kResourceHorses);
    if (tradeMetric != 0) {
      int assignAmount = static_cast<int>(tradeMetric) / 2;
      if (assignAmount > 4) {
        assignAmount = 5;
      }
      owner->SetItemPotentials(5, static_cast<short>(assignAmount));
      return;
    }
    owner->SetItemPotentials(5, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0052fba0
void TForeignMinister::ReplyToTradeOffer(short targetNation, short amount, short maximumAmount,
                                         short resourceCode) {
  TGreatPower* owner = greatPower;
  unsigned int dispatchAmount = amount;
  if (resourceCode == interiorBidResource) {
    if (interiorBidAmount < static_cast<short>(dispatchAmount)) {
      dispatchAmount = static_cast<unsigned short>(interiorBidAmount);
    }
    short availableAmount = owner->GetUnreservedMerchantCapacity(resourceCode);
    if (availableAmount < static_cast<short>(dispatchAmount)) {
      g_pTradeMgr->SetDealResults(
          owner->nationSlot, targetNation,
          static_cast<int>(owner->GetUnreservedMerchantCapacity(resourceCode)), maximumAmount,
          resourceCode, 0, false);
      return;
    }
  } else {
    unsigned short ledgerAmount =
        static_cast<unsigned short>(purchasePriorityByResource[resourceCode]);
    short* ledgerEntry = &purchasePriorityByResource[resourceCode];
    if (static_cast<short>(ledgerAmount) < 1) {
      dispatchAmount = 0;
    } else if (static_cast<short>(ledgerAmount) < static_cast<short>(dispatchAmount)) {
      dispatchAmount = ledgerAmount;
    }
    short availableAmount = owner->GetUnreservedMerchantCapacity(resourceCode);
    if (availableAmount < static_cast<short>(dispatchAmount)) {
      dispatchAmount =
          static_cast<unsigned int>(owner->GetUnreservedMerchantCapacity(resourceCode));
    }
    *ledgerEntry = static_cast<short>(*ledgerEntry - static_cast<short>(dispatchAmount));
  }
  g_pTradeMgr->SetDealResults(owner->nationSlot, targetNation, static_cast<int>(dispatchAmount),
                              maximumAmount, resourceCode, 0, false);
}

// FUNCTION: IMPERIALISM 0x0052fcc0
void TForeignMinister::EndTradePhase() {
  interiorBidAmount = 0;
  priceCheckPending = 0;
  interiorBidResource = kNoInteriorBidResource;
  TGreatPower* owner = greatPower;
  if (owner->GetMerchantCapacity() == 0) {
    diplomacyPhaseCounter = static_cast<short>(diplomacyPhaseCounter + 1);
  }
  memset(purchasePriorityByResource, 0, sizeof(purchasePriorityByResource));
}

// FUNCTION: IMPERIALISM 0x0052fd10
void TForeignMinister::SetDiplomacyPolicies() {
  if (g_pSimMgr->GetEconomicTurn() == 1) {
    DoFirstTurnDiplomacy();
  }
  if (g_pSimMgr->GetEconomicTurn() == 2) {
    DoSecondTurnDiplomacy();
  }
  SetEmpirePolicies();
  DoProposeTreaties();
  GoodsMatchShipping();
  DoDevelopmentGrants();
}

// FUNCTION: IMPERIALISM 0x0052fd80
void TForeignMinister::DoFirstTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x0052fda0
void TForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x0052fdc0
void TForeignMinister::GoodsMatchShipping() {
  TGreatPower* owner = greatPower;
  bool matched = false;
  short terrainSlot = 7;
  do {
    if (terrainSlot >= kNationSlotCount) {
      break;
    }
    if (g_apTerrainTypeDescriptorTable[terrainSlot]->IsColonyOf(owner->nationSlot)) {
      matched = true;
    }
    ++terrainSlot;
  } while (!matched);

  int nation = 0;
  do {
    if (static_cast<short>(nation) != owner->nationSlot) {
      if (g_pSimMgr->ReallyInTheGame(nation)) {
        if (matched &&
            g_pDiplomacyTurnStateManager
                    ->relationStandingScores[owner->nationSlot * kNationSlotCount + nation] <
                0x96) {
          owner->TellColoniesToBoycott(nation, 1);
        } else {
          owner->TellColoniesToBoycott(nation, 0);
        }
      }
    }
    ++nation;
  } while (static_cast<short>(nation) < kMajorNationCount);
}

// FUNCTION: IMPERIALISM 0x0052fe90
void TForeignMinister::DoDevelopmentGrants() {
  TGreatPower* owner = greatPower;
  int availableBudget = static_cast<int>((owner->treasuryValue - 10000) * 0.5);
  if (availableBudget <= 1000) {
    return;
  }

  TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
  relationshipList->ISortedByRelationshipList();
  g_pDiplomacyTurnStateManager->BuildRelationshipList(owner->nationSlot, 0, relationshipList);

  short entryIndex = relationshipList->GetSize();
  while (entryIndex >= 1 && availableBudget > 1000) {
    RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
        relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
    short nationSlot = entry->nationSlot;
    if (entry->standingScore < 0xff &&
        g_pDiplomacyTurnStateManager->GetEmbassyStatus(owner->nationSlot, nationSlot) == 2) {
      int grantAmount = SelectDevelopmentGrantAmount(availableBudget);
      availableBudget -= static_cast<short>(grantAmount);
      owner->SetGrantPolicyTo(nationSlot, grantAmount);
      developmentGrantByNation[nationSlot] =
          static_cast<short>(developmentGrantByNation[nationSlot] + grantAmount);
    }
    --entryIndex;
  }

  if (availableBudget > 1000) {
    entryIndex = static_cast<short>(relationshipList->GetSize());
    while (entryIndex >= 1 && availableBudget > 1000) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      short nationSlot = entry->nationSlot;
      if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(owner->nationSlot, nationSlot) == 1) {
        int grantAmount = SelectDevelopmentGrantAmount(availableBudget);
        availableBudget -= static_cast<short>(grantAmount);
        owner->SetGrantPolicyTo(nationSlot, grantAmount);
        developmentGrantByNation[nationSlot] =
            static_cast<short>(developmentGrantByNation[nationSlot] + grantAmount);
        if (developmentGrantByNation[nationSlot] >= 5000) {
          g_pDiplomacyTurnStateManager->BuildEmbassy(kDiplomaticMissionEmbassy, owner->nationSlot,
                                                     nationSlot);
        }
      }
      --entryIndex;
    }
  }

  if (availableBudget > 1000) {
    entryIndex = static_cast<short>(relationshipList->GetSize());
    while (entryIndex >= 1 && availableBudget > 1000) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      if (entry->standingScore < 0xff && g_pDiplomacyTurnStateManager->GetEmbassyStatus(
                                             owner->nationSlot, entry->nationSlot) == 0) {
        owner->SetDiplomacyPolicyTo(entry->nationSlot, 0x133);
        availableBudget = 0;
      }
      --entryIndex;
    }
  }

  relationshipList->FreeList();
}

// FUNCTION: IMPERIALISM 0x00530200
void TForeignMinister::DoProposeTreaties() {
  for (short minorNation = 7; minorNation < kNationSlotCount; ++minorNation) {
    TMinor* minor = g_apSecondaryNationStateSlots[minorNation];
    if (minor == 0 ||
        g_pDiplomacyTurnStateManager->GetEmbassyStatus(greatPower->nationSlot, minorNation) != 2) {
      continue;
    }
    if (minor->WouldAcceptOffer(greatPower->nationSlot, kDiplomacyProposalJoinEmpire)) {
      if (!g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(minorNation,
                                                                       greatPower->nationSlot)) {
        greatPower->SetDiplomacyPolicyTo(minorNation, kDiplomacyProposalJoinEmpire);
      }
    } else if (g_pDiplomacyTurnStateManager->GetTreatyStatus(greatPower->nationSlot, minorNation) ==
               kDiplomacyRelationshipPeace) {
      greatPower->SetDiplomacyPolicyTo(minorNation, kDiplomacyProposalNonAggressionPact);
    }
  }

  if (!greatPower->HasEnemy()) {
    DoSelectEnemy();
  }

  short nationSlot = greatPower->nationSlot;
  if (abs(g_pSimMgr->economicTurn) % 4 != g_aDiplomacyPlanningQuarterPhaseByNation[nationSlot]) {
    return;
  }

  int armyStrengthInt = static_cast<int>(greatPower->GetMilitaryPower());
  if (armyStrengthInt < 1) {
    armyStrengthInt = 1;
  }
  float armyStrength = static_cast<float>(armyStrengthInt);

  int navyStrengthInt = static_cast<int>(greatPower->GetTotalNavalForce());
  if (navyStrengthInt < 1) {
    navyStrengthInt = 1;
  }
  float navyStrength = static_cast<float>(navyStrengthInt);

  float alliedArmyStrength = 0.0f;
  float alliedNavyStrength = 0.0f;
  int allianceCount = g_pDiplomacyTurnStateManager->GetNumAllies(greatPower->nationSlot);
  for (int allianceIndex = 0; allianceIndex < allianceCount; ++allianceIndex) {
    int allyNation =
        g_pDiplomacyTurnStateManager->GetAllyNumber(allianceIndex, greatPower->nationSlot);
    alliedArmyStrength += g_apNationStates[allyNation]->GetMilitaryPower();
    alliedNavyStrength += g_apNationStates[allyNation]->GetTotalNavalForce();
  }

  bool strongerTargetExists = false;
  float targetStrengthRatio[7];
  for (int targetNation = 0; targetNation < kMajorNationCount; ++targetNation) {
    targetStrengthRatio[targetNation] = 0.0f;
    if (targetNation == greatPower->nationSlot ||
        !g_pSimMgr->ReallyInTheGame(static_cast<short>(targetNation))) {
      continue;
    }

    if (g_pGlobalMapState->AreNationsBorderLinked(greatPower->nationSlot, targetNation)) {
      targetStrengthRatio[targetNation] = g_apNationStates[targetNation]->GetMilitaryPower() /
                                          (armyStrength + alliedArmyStrength * 0.25f);
    } else {
      targetStrengthRatio[targetNation] = g_apNationStates[targetNation]->GetTotalNavalForce() /
                                          (navyStrength + alliedNavyStrength * 0.25f);
    }
    if (greatPower->GetSeekAllianceNumber() < targetStrengthRatio[targetNation]) {
      strongerTargetExists = true;
    }
  }

  if (strongerTargetExists) {
    int selectedNation = -1;
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->ISortedByRelationshipList();
    g_pDiplomacyTurnStateManager->BuildRelationshipList(greatPower->nationSlot, 1,
                                                        relationshipList);
    for (int entryIndex = relationshipList->GetSize(); entryIndex >= 1 && selectedNation == -1;
         --entryIndex) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      int candidateNation = entry->nationSlot;
      if (g_pDiplomacyTurnStateManager->GetTreatyStatus(greatPower->nationSlot,
                                                        static_cast<short>(candidateNation)) !=
              kDiplomacyRelationshipAlliance &&
          !g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(candidateNation,
                                                                       greatPower->nationSlot)) {
        selectedNation = candidateNation;
      }
    }
    if (selectedNation != -1) {
      greatPower->SetDiplomacyPolicyTo(static_cast<short>(selectedNation),
                                       kDiplomacyProposalAlliance);
    }
    relationshipList->FreeList();
  }

  for (int policyTargetNation = 0; policyTargetNation < kMajorNationCount; ++policyTargetNation) {
    if (policyTargetNation == greatPower->nationSlot ||
        !g_pSimMgr->ReallyInTheGame(static_cast<short>(policyTargetNation)) ||
        !g_pDiplomacyTurnStateManager->AreInEstablishedWar(greatPower->nationSlot,
                                                           policyTargetNation)) {
      continue;
    }

    float warThreshold = greatPower->GetPeaceThreat(policyTargetNation);
    if (greatPower->GetSeekPeaceNumber() < warThreshold) {
      greatPower->SetDiplomacyPolicyTo(static_cast<short>(policyTargetNation),
                                       kDiplomacyProposalPeaceTreaty);
      continue;
    }
    if (g_pSimMgr->economicTurn / 4 >= 0x46 || DeservesToBeEnemy(policyTargetNation)) {
      continue;
    }

    bool targetOwnsFormerProvince = false;
    TLongintList* targetRegions = g_apNationStates[policyTargetNation]->ownedRegionList;
    for (int regionIndex = 1; regionIndex < targetRegions->GetSize() && !targetOwnsFormerProvince;
         ++regionIndex) {
      int regionId = targetRegions->At(regionIndex);
      if (g_pGlobalMapState->cityScoreTable[regionId].formerOwnerNationCode ==
          greatPower->nationSlot) {
        targetOwnsFormerProvince = true;
      }
    }
    if (targetOwnsFormerProvince) {
      continue;
    }

    int recoveredProvinceCount = 0;
    TLongintList* ownerRegions = greatPower->ownedRegionList;
    for (int ownerRegionIndex = 1; ownerRegionIndex < ownerRegions->GetSize(); ++ownerRegionIndex) {
      int regionId = ownerRegions->At(ownerRegionIndex);
      if (g_pGlobalMapState->cityScoreTable[regionId].formerOwnerNationCode == policyTargetNation) {
        ++recoveredProvinceCount;
      }
    }
    int requiredProvinceCount = (g_pSimMgr->economicTurn / 4 + 10) / 10;
    if (recoveredProvinceCount >= requiredProvinceCount) {
      greatPower->SetDiplomacyPolicyTo(static_cast<short>(policyTargetNation),
                                       kDiplomacyProposalPeaceTreaty);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005308b0
bool TForeignMinister::DeservesToBeEnemy(int nationCode) {
  // Two difficulty-indexed threshold rows (A = [difficulty], B = [difficulty + 5]).
  int thresholds[10] = {0x15, 0x12, 0xf, 0xd, 0xb, 0x1b, 0x17, 0x13, 0x10, 0xe};
  int difficulty = g_pSimMgr->difficultyLevel; // [g_pSimMgr + 0x40] scenario/difficulty index
  int thresholdA = thresholds[difficulty];
  int thresholdB = thresholds[difficulty + 5];
  bool result = false;

  TGreatPower* ownerGP = greatPower;
  bool linked = g_pGlobalMapState->AreNationsBorderLinked(ownerGP->nationSlot, nationCode);
  if (linked == 0) {
    if (thresholdB < ownerGP->GetArmsInNavy()) {
      int scoreA = static_cast<int>(ownerGP->ComputeNavyScoreRatioVsNation(nationCode));
      int scoreB = static_cast<int>(ownerGP->ComputeNavyScoreStandingRatioVsNation(nationCode));
      float average = static_cast<float>((scoreA + scoreB) / 2);
      if (ownerGP->GetWarNumber() <= average) {
        result = true;
      }
    }
  } else {
    if (thresholdA < ownerGP->GetArmsInArmy()) {
      int scoreA = static_cast<int>(ownerGP->ComputeArmyScoreRatioVsNation(nationCode));
      int scoreB = static_cast<int>(ownerGP->ComputeArmyScoreStandingRatioVsNation(nationCode));
      int calendarYear = g_pSimMgr->finalCouncilYear;
      int difficultyDivisors[5] = {calendarYear, calendarYear / 2, calendarYear / 3,
                                   calendarYear / 5, 0};
      int campaignProgress = (g_pSimMgr->economicTurn / 4 + calendarYear) /
                             (difficultyDivisors[g_pSimMgr->difficultyLevel] + calendarYear);
      float average = static_cast<float>(static_cast<int>(
          static_cast<float>(campaignProgress) * static_cast<float>((scoreA + scoreB) / 2)));
      if (ownerGP->GetWarNumber() <= average) {
        return true;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x00530b30
void TForeignMinister::DoSelectEnemy() {
  for (int nationSlot = 0; nationSlot < kMajorNationCount; ++nationSlot) {
    if (greatPower->HasEnemy()) {
      return;
    }
    if (nationSlot != greatPower->nationSlot && g_pSimMgr->ReallyInTheGame(nationSlot) &&
        DeservesToBeEnemy(nationSlot)) {
      greatPower->SetEnemy(nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00530bb0
void TForeignMinister::SetEmpirePolicies() {
  TGreatPower* owner = greatPower;

  if (abs(g_pSimMgr->economicTurn) % 4 == 0 && !owner->WereAllOfferedGoodsSold()) {
    bool keepSearching = true;
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->ISortedByRelationshipList();
    g_pDiplomacyTurnStateManager->BuildRelationshipList(owner->nationSlot, 0, relationshipList);
    short entryIndex = relationshipList->GetSize();
    while (entryIndex >= 1 && keepSearching) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      int selectedMajor = g_pDiplomacyTurnStateManager->GetFavoriteTradePartner(entry->nationSlot);
      if (selectedMajor != owner->nationSlot && entry->standingScore > 0x31 &&
          owner->tradePolicyByNation[entry->nationSlot] != 300) {
        owner->ImproveTradePolicyTo(entry->nationSlot);
        keepSearching = false;
      }
      --entryIndex;
    }
    relationshipList->FreeList();
  }

  if (owner->GetMerchantCapacity() > 0) {
    int policyCategory = -1;
    for (short resourceKind = 0; resourceKind < kMajorNationCount && policyCategory == -1;
         ++resourceKind) {
      if (owner->unfilledTradeTurnCountsByResource[resourceKind] > 2) {
        policyCategory = resourceKind;
      }
    }

    if (policyCategory != -1) {
      int selectedMinor = -1;
      TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
      relationshipList->ISortedByRelationshipList();
      g_pDiplomacyTurnStateManager->BuildRelationshipList(owner->nationSlot, 0, relationshipList);
      int entryIndex = relationshipList->GetSize();
      while (entryIndex > 0 && selectedMinor == -1) {
        RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
            relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
        short minorNation = entry->nationSlot;
        if (g_pTradeMgr->categoryRows[policyCategory].tradeOfferCells[minorNation + 0x2e] != 0 &&
            owner->tradePolicyByNation[minorNation] != 300) {
          selectedMinor = minorNation;
        }
        --entryIndex;
      }
      relationshipList->FreeList();

      if (selectedMinor != -1) {
        short compatibility =
            g_pDiplomacyTurnStateManager->GetEmbassyStatus(owner->nationSlot, selectedMinor);
        if (compatibility < 1) {
          owner->SetDiplomacyPolicyTo(static_cast<short>(selectedMinor), 0x133);
        } else {
          owner->ImproveTradePolicyTo(static_cast<short>(selectedMinor));
        }
      }
    }
  }

  for (short minorNation = 7; minorNation < kNationSlotCount; ++minorNation) {
    if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(owner->nationSlot, minorNation) >= 1 &&
        owner->tradePolicyByNation[minorNation] > 0x5f &&
        owner->tradePolicyByNation[minorNation] < 300 &&
        g_apTerrainTypeDescriptorTable[minorNation]->encodedNationSlot == -1) {
      owner->SetTradePolicyTo(static_cast<NationSlot>(minorNation), 0x5f);
    }
  }

  if (owner->treasuryValue < 0) {
    for (short minorNation = 7; minorNation < kNationSlotCount; ++minorNation) {
      if (owner->tradePolicyByNation[minorNation] < 0x4b) {
        owner->SetTradePolicyTo(static_cast<NationSlot>(minorNation), 0x4b);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00530fa0
void TForeignMinister::ReplyToDiplomacyOffers(short queueIndex) {
  struct DiplomacyProposalRecord {
    DiplomacyProposalCodeStorage proposalCode;
    NationSlot targetNation;
  };

  TGreatPower* gp = greatPower;
  bool valid = 0;
  DiplomacyProposalRecord* record = static_cast<DiplomacyProposalRecord*>(
      gp->proposalQueue->GetPtrListEntryByOneBasedIndex(queueIndex));
  NationSlot targetNation = record->targetNation;
  if (gp->diplomacyPolicyByNation[targetNation] == record->proposalCode) {
    valid = 1;
  } else {
    switch (record->proposalCode) {
    case kDiplomacyProposalJoinEmpire:
      valid = 0;
      break;
    case kDiplomacyProposalAlliance:
      if (g_pDiplomacyTurnStateManager->GetTreatyStatus(gp->nationSlot, targetNation) !=
          kDiplomacyRelationshipPeace) {
        valid = 0;
      } else {
        valid = gp->PassesDiplomacyStrengthThresholdForTarget(targetNation);
      }
      break;
    case kDiplomacyProposalNonAggressionPact:
      valid = 1;
      break;
    case kDiplomacyProposalPeaceTreaty:
      valid = gp->EvaluateJoinWarAgainstNationAndQueueEvent(targetNation);
      if (valid == 0) {
        break;
      }
      g_pNewsMgr->AddTreatyEvent(kInterNationEventNationJoinedWar, gp->nationSlot, targetNation,
                                 false);
      break;
    case kDiplomacyProposalJoinEmpireWithWarEntanglements:
      valid = (!g_pDiplomacyTurnStateManager->HasAllianceGuardForNationPair(targetNation,
                                                                            gp->nationSlot));
      break;
    }
  }
  if (valid != 0) {
    gp->AcceptOffer(queueIndex);
    return;
  }
  gp->RejectOffer(queueIndex);
}

// FUNCTION: IMPERIALISM 0x00531110
void TForeignMinister::FinishDiplomacyPhase() {}
