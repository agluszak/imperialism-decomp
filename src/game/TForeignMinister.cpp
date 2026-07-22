#include "game/TForeignMinister.h"

#include "game/TTradeMgr.h"
#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"
#include "game/TMapMgr.h"
#include "game/TLongintList.h"
#include "game/TMinisterBaseOrderArray.h"
#include "game/TMinor.h"
#include "game/TSimMgr.h"
#include "game/TNewsMgr.h"
#include "game/mfc.h"
#include "game/TStream.h"
#include "game/nation_stream_serialization.h"

#include <stdlib.h>

#include "game/nation_slot_eligibility.h"

static const short kNoInteriorBidResource = static_cast<short>(0xfff6);

namespace {

struct MinisterPriorityEntry {
  short resourceCode;
  short priority;
  short rank;
};

struct RelationshipRankEntry {
  short nationSlot;
  short standing;
};

static __inline int SelectDevelopmentGrantAmount(int availableBudget) {
  if (availableBudget < 3000) {
    return 1000;
  }
  if (availableBudget < 5000) {
    return 3000;
  }
  return availableBudget < 10000 ? 5000 : 10000;
}

} // namespace
// SYNTHETIC: IMPERIALISM 0x0052efd0
// TForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x0052f050
// TForeignMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x0052f070
TForeignMinister::TForeignMinister() : TMinister() {
  memset(tradePartnerEnabled49, 1, sizeof(tradePartnerEnabled49));
  memset(developmentGrantByNation50, 0, sizeof(developmentGrantByNation50));
  capabilityFlag16 = 0;
  field48 = 0;
  tradeBidRefreshInterval1a = 5;
  interiorOrderKind1c = 2;
}

// SYNTHETIC: IMPERIALISM 0x0052f0e0
// TForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0052f130
void TForeignMinister::InitializeStateAndCounters(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  interiorBidResource10 = kNoInteriorBidResource;
  interiorBidAmount12 = 0;
  capabilityFlag14 = 0;
  diplomacyPhaseCounter18 = 0;
  memset(purchasePriorityByResource1e, 0, sizeof(purchasePriorityByResource1e));
  for (int i = 0; i < 4; ++i) {
    preferredResourceSlots40[i] = kNoInteriorBidResource;
  }
}

// FUNCTION: IMPERIALISM 0x0052f180
void TForeignMinister::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&skillIndexC, 2);
  stream->ReadBytes(&interiorBidResource10, 2);
  stream->ReadBytes(&interiorBidAmount12, 2);
  stream->ReadBytes(&capabilityFlag14, 2);
  stream->ReadBytes(&capabilityFlag16, 2);
  stream->ReadBytes(&diplomacyPhaseCounter18, 2);
  stream->ReadBytes(&tradeBidRefreshInterval1a, 2);
  stream->ReadBytes(&interiorOrderKind1c, 2);
  stream->ReadBytes(purchasePriorityByResource1e, sizeof(purchasePriorityByResource1e));
  SwapShortArrayBytes(purchasePriorityByResource1e, 0x11);
  stream->ReadBytes(preferredResourceSlots40, sizeof(preferredResourceSlots40));
  SwapShortArrayBytes(preferredResourceSlots40, 4);
  stream->ReadBytes(&field48, 1);
  stream->ReadBytes(tradePartnerEnabled49, sizeof(tradePartnerEnabled49));
  if (g_nSaveFormatVersion >= 0x15) {
    stream->ReadBytes(developmentGrantByNation50, sizeof(developmentGrantByNation50));
    SwapShortArrayBytes(developmentGrantByNation50, 0x17);
  }
}

// FUNCTION: IMPERIALISM 0x0052f2b0
void TForeignMinister::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&skillIndexC, 2);
  stream->WriteBytesSlot78(&interiorBidResource10, 2);
  stream->WriteBytesSlot78(&interiorBidAmount12, 2);
  stream->WriteBytesSlot78(&capabilityFlag14, 2);
  stream->WriteBytesSlot78(&capabilityFlag16, 2);
  stream->WriteBytesSlot78(&diplomacyPhaseCounter18, 2);
  stream->WriteBytesSlot78(&tradeBidRefreshInterval1a, 2);
  stream->WriteBytesSlot78(&interiorOrderKind1c, 2);
  WriteShortArrayElems(stream, purchasePriorityByResource1e, 0x11);
  WriteShortArrayElems(stream, preferredResourceSlots40, 4);
  stream->WriteBytesSlot78(&field48, 1);
  stream->WriteBytesSlot78(tradePartnerEnabled49, sizeof(tradePartnerEnabled49));
  WriteShortArrayElems(stream, developmentGrantByNation50, 0x17);
}

// FUNCTION: IMPERIALISM 0x0052f430
short TForeignMinister::GetRankingCriterionForGP(short nationSlot) {
  short relationTotal = 0;
  for (short otherNation = 0; otherNation < 0x17; ++otherNation) {
    if (otherNation != nationSlot && g_apTerrainTypeDescriptorTable[otherNation] != 0) {
      relationTotal = static_cast<short>(
          relationTotal + g_pDiplomacyTurnStateManager
                              ->relationStandingScoreMatrix79c[nationSlot * 0x17 + otherNation]);
    }
  }
  return static_cast<short>(relationTotal / (g_pSimMgr->GetNumCountries() - 1));
}

// FUNCTION: IMPERIALISM 0x0052f4b0
void TForeignMinister::InitializeTradeStatus() {
  // Seven-byte fill of the partner flags (bytes 0x49-0x4f) with 0x01; MSVC inlines it as
  // a 0x01010101 dword + word + byte store.
  memset(this->tradePartnerEnabled49, 1, 7);
  TGreatPower* ownerGP = this->ownerContextAt04;
  this->capabilityFlag16 = 0;
  if (ownerGP->treasuryValue10 < 0) {
    this->capabilityFlag14 = 1;
  }
}

// FUNCTION: IMPERIALISM 0x0052f4f0
void TForeignMinister::PleaseBuy(short index, short delta) {
  purchasePriorityByResource1e[index] =
      static_cast<short>(purchasePriorityByResource1e[index] + delta);
}

// FUNCTION: IMPERIALISM 0x0052f520
void TForeignMinister::PriceCheck() {
  this->capabilityFlag14 = 1;
}

// FUNCTION: IMPERIALISM 0x0052f540
void TForeignMinister::SetInteriorMinisterBid(short primary, short secondary) {
  this->interiorBidResource10 = primary;
  this->interiorBidAmount12 = secondary;
}

// FUNCTION: IMPERIALISM 0x0052f570
void TForeignMinister::SetBuyPriorities() {
  TMinisterBaseOrderArray* priorities = new TMinisterBaseOrderArray();

  for (short resourceCode = 0; resourceCode < 0x11; ++resourceCode) {
    if (purchasePriorityByResource1e[resourceCode] != 0) {
      MinisterPriorityEntry entry;
      entry.resourceCode = resourceCode;
      entry.priority = static_cast<short>(purchasePriorityByResource1e[resourceCode] + 1);
      priorities->InsertCopiedRecordSortedByComparator(&entry);
    }
  }

  for (int preferenceIndex = 0; preferenceIndex < 4; ++preferenceIndex) {
    bool alreadyPresent = false;
    for (short entryIndex = 1; entryIndex <= priorities->GetSize() && !alreadyPresent;
         ++entryIndex) {
      MinisterPriorityEntry* entry = static_cast<MinisterPriorityEntry*>(
          priorities->GetPtrListEntryByOneBasedIndex(entryIndex));
      if (entry->resourceCode == preferredResourceSlots40[preferenceIndex]) {
        alreadyPresent = true;
      }
    }
    if (!alreadyPresent) {
      MinisterPriorityEntry entry;
      entry.resourceCode = preferredResourceSlots40[preferenceIndex];
      entry.priority = 1;
      priorities->InsertCopiedRecordSortedByComparator(&entry);
    }
  }

  for (int selectedIndex = 0; selectedIndex < 4; ++selectedIndex) {
    MinisterPriorityEntry* entry = static_cast<MinisterPriorityEntry*>(
        priorities->GetPtrListEntryByOneBasedIndex(selectedIndex + 1));
    preferredResourceSlots40[selectedIndex] = entry->resourceCode;
  }
  priorities->ReleasePtrList();
}

// FUNCTION: IMPERIALISM 0x0052f730
int TForeignMinister::WeNeedMoney() {
  // The original reloads the owner (this->ownerContextAt04) once per comparison.
  TGreatPower* gp = this->ownerContextAt04;
  short cap = gp->tradeCapacity;
  if (gp->GetDiplomacyExternalStateByTarget(0xd) < cap) {
    gp = this->ownerContextAt04;
    cap = gp->tradeCapacity;
    if (gp->GetDiplomacyExternalStateByTarget(0xe) < cap) {
      gp = this->ownerContextAt04;
      cap = gp->tradeCapacity;
      if (gp->GetDiplomacyExternalStateByTarget(0xf) < cap) {
        return 0;
      }
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0052f7b0
void TForeignMinister::ArrangeMaterialsOffers() {
  TGreatPower* owner = this->ownerContextAt04;

  if (interiorBidResource10 != kNoInteriorBidResource) {
    TSortedByRelationshipList* relationshipList =
        static_cast<TSortedByRelationshipList*>(TSortedByRelationshipList::CreateObject());
    if (relationshipList != 0) {
      relationshipList->recordSize14 = 4;
    }
    if (relationshipList != 0) {
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(owner->nationSlot, 1,
                                                                relationshipList);
      short* nationSlotPtr = static_cast<short*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(relationshipList->GetSize()));
      g_apNationStates[*nationSlotPtr]->AssignNeedSlotFromSourceSlot19C(interiorBidResource10,
                                                                        owner->nationSlot);
      relationshipList->ReleasePtrList();
    }
  }

  if (purchasePriorityByResource1e[5] > 0) {
    bool foundFallbackNation = false;
    int trialIndex = 1;
    int fallbackNationSlot = 0;
    do {
      if (foundFallbackNation) {
        break;
      }
      fallbackNationSlot = rand() % 7;
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(
              static_cast<short>(fallbackNationSlot)) != 0) {
        if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(fallbackNationSlot,
                                                                    owner->nationSlot) == 0 &&
            fallbackNationSlot != owner->nationSlot) {
          foundFallbackNation = true;
        }
      }
      trialIndex = trialIndex + 1;
    } while (trialIndex < 0x14);
    if (foundFallbackNation) {
      g_apNationStates[fallbackNationSlot]->AssignNeedSlotFromSourceSlot19C(5, owner->nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052f940
void TForeignMinister::SetTradeBids() {
  this->InitializeTradeStatus();
  TGreatPower* owner = this->ownerContextAt04;
  int skipMissionSlot1A = 0;
  if (diplomacyPhaseCounter18 < tradeBidRefreshInterval1a) {
    if (this->WeNeedMoney() == 0) {
      skipMissionSlot1A = 1;
    }
  }
  if (skipMissionSlot1A == 0) {
    owner->foreignMinister->GoodsMatchShipping();
    diplomacyPhaseCounter18 = 0;
  }
  this->SetBuyPriorities();
  if (interiorBidResource10 != kNoInteriorBidResource) {
    short idx = interiorBidResource10;
    purchasePriorityByResource1e[idx] = interiorBidAmount12;
    owner->SetDiplomacyState1c6ClampedToCounterA4(idx, static_cast<short>(-1));
  }
}

// FUNCTION: IMPERIALISM 0x0052f9d0
void TForeignMinister::DoUsualSubsidyRule() {
  TGreatPower* owner = this->ownerContextAt04;
  short nationSlot = owner->nationSlot;
  static const short kOrderKinds[] = {0, 1, 2, 3, 4, 5, 6};
  int loopCount =
      (g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[0x13] == 2) + 5;
  if (loopCount != 0) {
    const short* orderKindCursor = kOrderKinds;
    do {
      int roll = rand();
      short orderKind = *orderKindCursor;
      short weightThreshold =
          g_pNationInteractionStateManager->QueryProposalWeightSlot4C(orderKind);
      if (roll % 100 + 200 < static_cast<int>(weightThreshold)) {
        short metric = owner->GetDiplomacyExternalStateByTarget(orderKind);
        if (metric == 0) {
          owner->AssignNeedSlotFromSourceSlot19C(orderKind, 0);
        } else {
          int assignAmount = static_cast<int>(metric) / 2;
          if (assignAmount > 4) {
            assignAmount = 5;
          }
          owner->AssignNeedSlotFromSourceSlot19C(orderKind, assignAmount);
        }
      }
      orderKindCursor = orderKindCursor + 1;
      loopCount = loopCount + -1;
    } while (loopCount != 0);
  }

  int roll = rand();
  short tradeWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(5);
  if (roll % 100 + 200 < static_cast<int>(tradeWeight)) {
    short tradeMetric = owner->GetDiplomacyExternalStateByTarget(5);
    if (tradeMetric != 0) {
      int assignAmount = static_cast<int>(tradeMetric) / 2;
      if (assignAmount > 4) {
        assignAmount = 5;
      }
      owner->AssignNeedSlotFromSourceSlot19C(5, assignAmount);
      return;
    }
    owner->AssignNeedSlotFromSourceSlot19C(5, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0052fba0
void TForeignMinister::ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode) {
  (void)arg1;
  TGreatPower* owner = this->ownerContextAt04;
  unsigned int dispatchAmount = static_cast<unsigned int>(arg3);
  if (resourceCode == interiorBidResource10) {
    if (interiorBidAmount12 < static_cast<short>(dispatchAmount)) {
      dispatchAmount = static_cast<unsigned short>(interiorBidAmount12);
    }
    short availableAmount =
        static_cast<short>(owner->GetEffectiveDiplomacyCounterA2ForCode(resourceCode));
    if (availableAmount < static_cast<short>(dispatchAmount)) {
      g_pNationInteractionStateManager->DispatchProposalAmountSlot60(
          owner->nationSlot, arg2,
          static_cast<int>(owner->GetEffectiveDiplomacyCounterA2ForCode(resourceCode)),
          static_cast<int>(dispatchAmount), resourceCode, 0, 0);
      return;
    }
  } else {
    unsigned short ledgerAmount =
        static_cast<unsigned short>(purchasePriorityByResource1e[resourceCode]);
    short* ledgerEntry = &purchasePriorityByResource1e[resourceCode];
    if (static_cast<short>(ledgerAmount) < 1) {
      dispatchAmount = 0;
    } else if (static_cast<short>(ledgerAmount) < static_cast<short>(dispatchAmount)) {
      dispatchAmount = ledgerAmount;
    }
    short availableAmount =
        static_cast<short>(owner->GetEffectiveDiplomacyCounterA2ForCode(resourceCode));
    if (availableAmount < static_cast<short>(dispatchAmount)) {
      dispatchAmount =
          static_cast<unsigned int>(owner->GetEffectiveDiplomacyCounterA2ForCode(resourceCode));
    }
    *ledgerEntry = static_cast<short>(*ledgerEntry - static_cast<short>(dispatchAmount));
  }
  g_pNationInteractionStateManager->DispatchProposalAmountSlot60(
      owner->nationSlot, arg2, static_cast<int>(dispatchAmount), arg3, resourceCode, 0, 0);
}

// FUNCTION: IMPERIALISM 0x0052fcc0
void TForeignMinister::EndTradePhase() {
  interiorBidAmount12 = 0;
  capabilityFlag14 = 0;
  interiorBidResource10 = kNoInteriorBidResource;
  TGreatPower* owner = this->ownerContextAt04;
  if (owner->GetDiplomacyCounterA2() == 0) {
    diplomacyPhaseCounter18 = static_cast<short>(diplomacyPhaseCounter18 + 1);
  }
  memset(purchasePriorityByResource1e, 0, sizeof(purchasePriorityByResource1e));
}

// FUNCTION: IMPERIALISM 0x0052fd10
void TForeignMinister::SetDiplomacyPolicies() {
  if (g_pSimMgr->GetEconomicTurn() == 1) {
    this->DoFirstTurnDiplomacy();
  }
  if (g_pSimMgr->GetEconomicTurn() == 2) {
    this->DoSecondTurnDiplomacy();
  }
  this->SetEmpirePolicies();
  this->DoProposeTreaties();
  this->GoodsMatchShipping();
  this->DoDevelopmentGrants();
}

// FUNCTION: IMPERIALISM 0x0052fd80
void TForeignMinister::DoFirstTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x0052fda0
void TForeignMinister::DoSecondTurnDiplomacy() {}

// FUNCTION: IMPERIALISM 0x0052fdc0
void TForeignMinister::GoodsMatchShipping() {
  TGreatPower* owner = this->ownerContextAt04;
  bool matched = false;
  short terrainSlot = 7;
  do {
    if (terrainSlot >= 0x17) {
      break;
    }
    if (g_apTerrainTypeDescriptorTable[terrainSlot]->IsEncodedNationSlotMinus200Equal(
            owner->nationSlot) != 0) {
      matched = true;
    }
    ++terrainSlot;
  } while (!matched);

  int nation = 0;
  do {
    if (static_cast<short>(nation) != owner->nationSlot) {
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nation) != 0) {
        if (matched &&
            g_pDiplomacyTurnStateManager
                    ->relationStandingScoreMatrix79c[owner->nationSlot * 0x17 + nation] < 0x96) {
          owner->SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(nation, 1);
        } else {
          owner->SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(nation, 0);
        }
      }
    }
    ++nation;
  } while (static_cast<short>(nation) < 7);
}

// FUNCTION: IMPERIALISM 0x0052fe90
void TForeignMinister::DoDevelopmentGrants() {
  TGreatPower* owner = ownerContextAt04;
  int availableBudget = static_cast<int>((owner->treasuryValue10 - 10000) * 0.5);
  if (availableBudget <= 1000) {
    return;
  }

  TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
  relationshipList->InitializeRelationshipRecordSize();
  g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(owner->nationSlot, 0, relationshipList);

  short entryIndex = static_cast<short>(relationshipList->GetSize());
  while (entryIndex >= 1 && availableBudget > 1000) {
    RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
        relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
    short nationSlot = entry->nationSlot;
    if (entry->standing < 0xff && g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
                                      owner->nationSlot, nationSlot) == 2) {
      int grantAmount = SelectDevelopmentGrantAmount(availableBudget);
      availableBudget -= static_cast<short>(grantAmount);
      owner->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(nationSlot, grantAmount);
      developmentGrantByNation50[nationSlot] =
          static_cast<short>(developmentGrantByNation50[nationSlot] + grantAmount);
    }
    --entryIndex;
  }

  if (availableBudget > 1000) {
    entryIndex = static_cast<short>(relationshipList->GetSize());
    while (entryIndex >= 1 && availableBudget > 1000) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      short nationSlot = entry->nationSlot;
      if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(owner->nationSlot,
                                                                            nationSlot) == 1) {
        int grantAmount = SelectDevelopmentGrantAmount(availableBudget);
        availableBudget -= static_cast<short>(grantAmount);
        owner->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(nationSlot, grantAmount);
        developmentGrantByNation50[nationSlot] =
            static_cast<short>(developmentGrantByNation50[nationSlot] + grantAmount);
        if (developmentGrantByNation50[nationSlot] >= 5000) {
          g_pDiplomacyTurnStateManager->SetNationPairSpecialRelationFlagAndQueueEvent14Or16(
              2, owner->nationSlot, nationSlot);
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
      if (entry->standing < 0xff &&
          g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
              owner->nationSlot, entry->nationSlot) == 0) {
        owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(entry->nationSlot, 0x133);
        availableBudget = 0;
      }
      --entryIndex;
    }
  }

  relationshipList->ReleasePtrList();
}

// TODO: port the 1359-byte SEH turn-event-hint queuer body (unported stub for now).
// FUNCTION: IMPERIALISM 0x00530200
void TForeignMinister::DoProposeTreaties() {
  TGreatPower* owner = ownerContextAt04;

  for (short minorNation = 7; minorNation < 0x17; ++minorNation) {
    TMinor* minor = g_apSecondaryNationStateSlots[minorNation];
    if (minor == 0 || g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
                          owner->nationSlot, minorNation) != 2) {
      continue;
    }
    if (minor->CanInitiateJoinEmpireProposalToTarget(owner->nationSlot, 0x12d) != 0) {
      if (g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(minorNation, owner->nationSlot) ==
          0) {
        owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(minorNation, 0x12d);
      }
    } else if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(owner->nationSlot,
                                                                                minorNation) == 4) {
      owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(minorNation, 0x12f);
    }
  }

  if (owner->HasActiveCandidateNationSlots() == 0) {
    DoSelectEnemy();
  }

  short nationSlot = owner->nationSlot;
  if (abs(g_pSimMgr->economicTurn) % 4 != g_aDiplomacyPlanningQuarterPhaseByNation[nationSlot]) {
    return;
  }

  int armyStrengthInt = static_cast<int>(owner->GetScoreFactorSlot23C());
  if (armyStrengthInt < 1) {
    armyStrengthInt = 1;
  }
  float armyStrength = static_cast<float>(armyStrengthInt);

  int navyStrengthInt = static_cast<int>(owner->GetScoreFactorSlot240());
  if (navyStrengthInt < 1) {
    navyStrengthInt = 1;
  }
  float navyStrength = static_cast<float>(navyStrengthInt);

  float alliedArmyStrength = 0.0f;
  float alliedNavyStrength = 0.0f;
  int allianceCount =
      g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(owner->nationSlot);
  for (int allianceIndex = 0; allianceIndex < allianceCount; ++allianceIndex) {
    int allyNation = g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allianceIndex,
                                                                                 owner->nationSlot);
    alliedArmyStrength += g_apNationStates[allyNation]->GetScoreFactorSlot23C();
    alliedNavyStrength += g_apNationStates[allyNation]->GetScoreFactorSlot240();
  }

  bool strongerTargetExists = false;
  float targetStrengthRatio[7];
  for (int targetNation = 0; targetNation < 7; ++targetNation) {
    targetStrengthRatio[targetNation] = 0.0f;
    if (targetNation == owner->nationSlot ||
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(targetNation)) == 0) {
      continue;
    }

    if (g_pGlobalMapState->AreNationsBorderLinked(owner->nationSlot, targetNation) != 0) {
      targetStrengthRatio[targetNation] = g_apNationStates[targetNation]->GetScoreFactorSlot23C() /
                                          (armyStrength + alliedArmyStrength * 0.25f);
    } else {
      targetStrengthRatio[targetNation] = g_apNationStates[targetNation]->GetScoreFactorSlot240() /
                                          (navyStrength + alliedNavyStrength * 0.25f);
    }
    if (owner->ComputeMinisterSkillFloatSlot89() < targetStrengthRatio[targetNation]) {
      strongerTargetExists = true;
    }
  }

  if (strongerTargetExists) {
    int selectedNation = -1;
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->InitializeRelationshipRecordSize();
    g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(owner->nationSlot, 1,
                                                              relationshipList);
    for (int entryIndex = relationshipList->GetSize(); entryIndex >= 1 && selectedNation == -1;
         --entryIndex) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      int candidateNation = entry->nationSlot;
      if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(
              owner->nationSlot, static_cast<short>(candidateNation)) != 2 &&
          g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(static_cast<short>(candidateNation),
                                                               owner->nationSlot) == 0) {
        selectedNation = candidateNation;
      }
    }
    if (selectedNation != -1) {
      owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(static_cast<short>(selectedNation),
                                                              0x12e);
    }
    relationshipList->ReleasePtrList();
  }

  for (int policyTargetNation = 0; policyTargetNation < 7; ++policyTargetNation) {
    if (policyTargetNation == owner->nationSlot ||
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(policyTargetNation)) ==
            0 ||
        g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
            owner->nationSlot, policyTargetNation) == 0) {
      continue;
    }

    float warThreshold = owner->ComputeWarThresholdSlotA3(policyTargetNation);
    if (owner->ComputeMinisterSkillFloatSlot8B() < warThreshold) {
      owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          static_cast<short>(policyTargetNation), 0x130);
      continue;
    }
    if (g_pSimMgr->economicTurn / 4 >= 0x46 || DeservesToBeEnemy(policyTargetNation) != 0) {
      continue;
    }

    bool targetOwnsFormerProvince = false;
    TLongintList* targetRegions = g_apNationStates[policyTargetNation]->ownedRegionList;
    for (int regionIndex = 1; regionIndex < targetRegions->GetSize() && !targetOwnsFormerProvince;
         ++regionIndex) {
      int regionId = targetRegions->At(regionIndex);
      if (g_pGlobalMapState->cityScoreTable[regionId].formerOwnerNationCode01 ==
          owner->nationSlot) {
        targetOwnsFormerProvince = true;
      }
    }
    if (targetOwnsFormerProvince) {
      continue;
    }

    int recoveredProvinceCount = 0;
    TLongintList* ownerRegions = owner->ownedRegionList;
    for (int ownerRegionIndex = 1; ownerRegionIndex < ownerRegions->GetSize(); ++ownerRegionIndex) {
      int regionId = ownerRegions->At(ownerRegionIndex);
      if (g_pGlobalMapState->cityScoreTable[regionId].formerOwnerNationCode01 ==
          policyTargetNation) {
        ++recoveredProvinceCount;
      }
    }
    int requiredProvinceCount = (g_pSimMgr->economicTurn / 4 + 10) / 10;
    if (recoveredProvinceCount >= requiredProvinceCount) {
      owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(
          static_cast<short>(policyTargetNation), 0x130);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005308b0
char TForeignMinister::DeservesToBeEnemy(int nationCode) {
  // Two difficulty-indexed threshold rows (A = [difficulty], B = [difficulty + 5]).
  int thresholds[10] = {0x15, 0x12, 0xf, 0xd, 0xb, 0x1b, 0x17, 0x13, 0x10, 0xe};
  int difficulty = g_pSimMgr->difficultyLevel; // [g_pSimMgr + 0x40] scenario/difficulty index
  int thresholdA = thresholds[difficulty];
  int thresholdB = thresholds[difficulty + 5];
  char result = 0;

  TGreatPower* ownerGP = this->ownerContextAt04;
  char linked = g_pGlobalMapState->AreNationsBorderLinked(ownerGP->nationSlot, nationCode);
  if (linked == 0) {
    if (thresholdB < ownerGP->SumNavyOrderPriorityForNationSlot86()) {
      int scoreA = static_cast<int>(ownerGP->ComputeNavyScoreRatioVsNation(nationCode));
      int scoreB = static_cast<int>(ownerGP->ComputeNavyScoreStandingRatioVsNation(nationCode));
      float average = static_cast<float>((scoreA + scoreB) / 2);
      if (ownerGP->ComputeMinisterSkillFloatSlot88() <= average) {
        result = 1;
      }
    }
  } else {
    if (thresholdA < ownerGP->ComputeSelectedMilitaryPowerScore()) {
      int scoreA = static_cast<int>(ownerGP->ComputeArmyScoreRatioVsNation(nationCode));
      int scoreB = static_cast<int>(ownerGP->ComputeArmyScoreStandingRatioVsNation(nationCode));
      float average = static_cast<float>((scoreA + scoreB) / 2);
      if (ownerGP->ComputeMinisterSkillFloatSlot88() <= average) {
        return 1;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x00530b30
void TForeignMinister::DoSelectEnemy() {
  // The original reloads the owning great power (this->ownerContextAt04) at each use
  // rather than caching it; access it inline so the same reload codegen is emitted.
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (this->ownerContextAt04->HasActiveCandidateNationSlots() != 0) {
      return;
    }
    if (nationSlot != this->ownerContextAt04->nationSlot &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
        this->DeservesToBeEnemy(nationSlot) != 0) {
      this->ownerContextAt04->SetCandidateNationFlagAndPortZoneState(nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00530bb0
void TForeignMinister::SetEmpirePolicies() {
  TGreatPower* owner = ownerContextAt04;

  if (abs(g_pSimMgr->economicTurn) % 4 == 0 &&
      owner->AreDiplomacyState1c6Slots13To16AllNonPositive() == 0) {
    bool keepSearching = true;
    TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
    relationshipList->InitializeRelationshipRecordSize();
    g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(owner->nationSlot, 0,
                                                              relationshipList);
    short entryIndex = static_cast<short>(relationshipList->GetSize());
    while (entryIndex >= 1 && keepSearching) {
      RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
          relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
      int selectedMajor =
          g_pDiplomacyTurnStateManager->SelectBestMajorNationForMinorByStandingAndNeed(
              entry->nationSlot);
      if (selectedMajor != owner->nationSlot && entry->standing > 0x31 &&
          owner->needLevelByNation[entry->nationSlot] != 300) {
        owner->DecrementNeedLevelByNationStep(entry->nationSlot);
        keepSearching = false;
      }
      --entryIndex;
    }
    relationshipList->ReleasePtrList();
  }

  if (owner->GetDiplomacyCounterA2() > 0) {
    int policyCategory = -1;
    for (short majorNation = 0; majorNation < 7 && policyCategory == -1; ++majorNation) {
      if (owner->diplomacyState1f4[majorNation] > 2) {
        policyCategory = majorNation;
      }
    }

    if (policyCategory != -1) {
      int selectedMinor = -1;
      TSortedByRelationshipList* relationshipList = new TSortedByRelationshipList();
      relationshipList->InitializeRelationshipRecordSize();
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(owner->nationSlot, 0,
                                                                relationshipList);
      int entryIndex = relationshipList->GetSize();
      while (entryIndex > 0 && selectedMinor == -1) {
        RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
            relationshipList->GetPtrListEntryByOneBasedIndex(entryIndex));
        short minorNation = entry->nationSlot;
        if (g_pNationInteractionStateManager->categoryRows[policyCategory]
                    .cells18[minorNation + 0x2e] != 0 &&
            owner->needLevelByNation[minorNation] != 300) {
          selectedMinor = minorNation;
        }
        --entryIndex;
      }
      relationshipList->ReleasePtrList();

      if (selectedMinor != -1) {
        short compatibility = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
            owner->nationSlot, selectedMinor);
        if (compatibility < 1) {
          owner->ApplyDiplomacyPolicyStateForTargetWithCostChecks(static_cast<short>(selectedMinor),
                                                                  0x133);
        } else {
          owner->DecrementNeedLevelByNationStep(static_cast<short>(selectedMinor));
        }
      }
    }
  }

  for (short minorNation = 7; minorNation < 0x17; ++minorNation) {
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(owner->nationSlot,
                                                                          minorNation) >= 1 &&
        owner->needLevelByNation[minorNation] > 0x5f &&
        owner->needLevelByNation[minorNation] < 300 &&
        g_apTerrainTypeDescriptorTable[minorNation]->encodedNationSlot == -1) {
      owner->SetTradePolicyTo(static_cast<NationSlot>(minorNation), 0x5f);
    }
  }

  if (owner->treasuryValue10 < 0) {
    for (short minorNation = 7; minorNation < 0x17; ++minorNation) {
      if (owner->needLevelByNation[minorNation] < 0x4b) {
        owner->SetTradePolicyTo(static_cast<NationSlot>(minorNation), 0x4b);
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00530fa0
void TForeignMinister::ReplyToDiplomacyOffers(short queueIndex) {
  TGreatPower* gp = this->ownerContextAt04;
  char valid = 0;
  short* record =
      static_cast<short*>(gp->proposalQueue->GetPtrListEntryByOneBasedIndex(queueIndex));
  short targetNation = record[1];
  if (gp->diplomacyPolicyByNation[targetNation] == record[0]) {
    valid = 1;
  } else {
    switch (record[0]) {
    case 0x12d:
      valid = 0;
      break;
    case 0x12e:
      if (g_pDiplomacyTurnStateManager->GetNationPairDiplomacyRelationCode(gp->nationSlot,
                                                                           targetNation) != 4) {
        valid = 0;
      } else {
        valid = gp->ReturnZeroSlot9D(targetNation);
      }
      break;
    case 0x12f:
      valid = 1;
      break;
    case 0x130:
      valid = gp->EvaluateJoinWarAgainstNationAndQueueEvent(targetNation);
      if (valid == 0) {
        gp->RejectOffer(queueIndex);
        return;
      }
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1c, gp->nationSlot,
                                                                          targetNation, '\0');
      break;
    case 0x132:
      valid =
          (g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(targetNation, gp->nationSlot) == 0);
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
