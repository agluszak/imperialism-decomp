#include "game/TForeignMinister.h"

#include "game/TTradeMgr.h"
#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/TNewsMgr.h"
#include "game/mfc.h"
#include "game/TStream.h"

#include "game/nation_slot_eligibility.h"

extern "C" int __cdecl rand(void);

static __inline unsigned int randValue(void) {
  return reinterpret_cast<unsigned int(__cdecl*)(void)>(rand)();
}

static const short kPrimaryNationUnset = static_cast<short>(0xfff6);
// SYNTHETIC: IMPERIALISM 0x0052efd0
// TForeignMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x0052f050
// TForeignMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TForeignMinister, TMinister)

// FUNCTION: IMPERIALISM 0x0052f070
TForeignMinister::TForeignMinister() : TMinister() {
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<unsigned int*>(raw + 0x49) = 0x01010101;
  *reinterpret_cast<unsigned short*>(raw + 0x4d) = 0x0101;
  raw[0x4f] = 1;
  unsigned int* block = reinterpret_cast<unsigned int*>(raw + 0x50);
  for (int i = 0; i < 0xb; ++i) {
    block[i] = 0;
  }
  *reinterpret_cast<unsigned short*>(raw + 0x7c) = 0;
  *reinterpret_cast<unsigned short*>(raw + 0x16) = 0;
  raw[0x48] = 0;
  *reinterpret_cast<short*>(raw + 0x1a) = 5;
  *reinterpret_cast<short*>(raw + 0x1c) = 2;
}

// SYNTHETIC: IMPERIALISM 0x0052f0e0
// TForeignMinister::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0052f130
void TForeignMinister::InitializeStateAndCounters(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x10) = kPrimaryNationUnset;
  *reinterpret_cast<short*>(raw + 0x12) = 0;
  *reinterpret_cast<short*>(raw + 0x14) = 0;
  *reinterpret_cast<short*>(raw + 0x18) = 0;
  unsigned int* block = reinterpret_cast<unsigned int*>(raw + 0x1e);
  for (int i = 0; i < 8; ++i) {
    block[i] = 0;
  }
  *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(block) + 0x20) = 0;
  *reinterpret_cast<unsigned int*>(raw + 0x40) = 0xfff6fff6;
  *reinterpret_cast<unsigned int*>(raw + 0x44) = 0xfff6fff6;
}

// FUNCTION: IMPERIALISM 0x0052f180
void TForeignMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x0052f2b0
void TForeignMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x0052f430
short TForeignMinister::DispatchNationStateEventCode10(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0052f4b0
void TForeignMinister::InitializeForeignMinisterStateFlags() {
  // Seven-byte fill of flags49 (bytes 0x49-0x4f) with 0x01; MSVC inlines this memset as
  // a 0x01010101 dword + word + byte store.
  memset(this->flags49, 1, 7);
  TGreatPower* ownerGP = this->ownerContextAt04;
  this->capabilityFlag16 = 0;
  if (ownerGP->treasuryValue10 < 0) {
    this->capabilityFlag14 = 1;
  }
}

// FUNCTION: IMPERIALISM 0x0052f4f0
void TForeignMinister::AddToForeignMinisterCounterAtIndex(short index, short delta) {
  this->counters1e[index] = static_cast<short>(this->counters1e[index] + delta);
}

// FUNCTION: IMPERIALISM 0x0052f520
void TForeignMinister::SetForeignMinisterReadyFlag14() {
  this->capabilityFlag14 = 1;
}

// FUNCTION: IMPERIALISM 0x0052f540
void TForeignMinister::SetForeignMinisterPrimaryAndSecondaryTargets(short primary,
                                                                    short secondary) {
  this->field10 = primary;
  this->field12 = secondary;
}

// FUNCTION: IMPERIALISM 0x0052f570
void TForeignMinister::MinisterSlot21() {}

// FUNCTION: IMPERIALISM 0x0052f730
int TForeignMinister::HasAnyOptionDToFMeetingNationThreshold() {
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
void TForeignMinister::Call8C() {
  char* raw = reinterpret_cast<char*>(this);
  TGreatPower* owner = this->ownerContextAt04;

  if (*reinterpret_cast<short*>(raw + 0x10) != kPrimaryNationUnset) {
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
      g_apNationStates[*nationSlotPtr]->AssignNeedSlotFromSourceSlot19C(
          *reinterpret_cast<short*>(raw + 0x10), owner->nationSlot);
      relationshipList->ReleasePtrList();
    }
  }

  if (this->capabilityFlag28 > 0) {
    bool foundFallbackNation = false;
    int trialIndex = 1;
    int fallbackNationSlot = 0;
    do {
      if (foundFallbackNation) {
        break;
      }
      fallbackNationSlot = randValue() % 7;
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
void TForeignMinister::Call90() {
  this->InitializeForeignMinisterStateFlags();
  char* raw = reinterpret_cast<char*>(this);
  TGreatPower* owner = this->ownerContextAt04;
  int skipMissionSlot1A = 0;
  if (*reinterpret_cast<short*>(raw + 0x18) < *reinterpret_cast<short*>(raw + 0x1a)) {
    if (this->HasAnyOptionDToFMeetingNationThreshold() == 0) {
      skipMissionSlot1A = 1;
    }
  }
  if (skipMissionSlot1A == 0) {
    owner->foreignMinister->UpdateNationInteractionEnableFlagsByTerrainAndRelation();
    *reinterpret_cast<unsigned short*>(raw + 0x18) = 0;
  }
  this->MinisterSlot21();
  if (*reinterpret_cast<short*>(raw + 0x10) != kPrimaryNationUnset) {
    short idx = *reinterpret_cast<short*>(raw + 0x10);
    *reinterpret_cast<short*>(raw + 0x1e + idx * 2) = *reinterpret_cast<short*>(raw + 0x12);
    owner->SetDiplomacyState1c6ClampedToCounterA4(idx, static_cast<short>(-1));
  }
}

// FUNCTION: IMPERIALISM 0x0052f9d0
void TForeignMinister::Call94() {
  TGreatPower* owner = this->ownerContextAt04;
  short nationSlot = owner->nationSlot;
  static const short kOrderKinds[] = {0, 1, 2, 3, 4, 5, 6};
  int loopCount =
      (g_pCityOrderCapabilityState->orderCapRows277[nationSlot].techStatusByTechId[0x13] == 2) + 5;
  if (loopCount != 0) {
    const short* orderKindCursor = kOrderKinds;
    do {
      int roll = randValue();
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

  int roll = randValue();
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
void TForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
  (void)arg1;
  char* raw = reinterpret_cast<char*>(this);
  TGreatPower* owner = this->ownerContextAt04;
  unsigned int dispatchAmount = static_cast<unsigned int>(arg3);
  short targetNationSlot = static_cast<short>(targetNation);

  if (targetNationSlot == *reinterpret_cast<short*>(raw + 0x10)) {
    if (static_cast<short>(*reinterpret_cast<unsigned short*>(raw + 0x12)) <
        static_cast<short>(dispatchAmount)) {
      dispatchAmount = *reinterpret_cast<unsigned short*>(raw + 0x12);
    }
    short availableAmount =
        static_cast<short>(owner->GetEffectiveDiplomacyCounterA2ForCode(targetNation));
    if (availableAmount < static_cast<short>(dispatchAmount)) {
      g_pNationInteractionStateManager->DispatchProposalAmountSlot60(
          owner->nationSlot, arg2,
          static_cast<int>(owner->GetEffectiveDiplomacyCounterA2ForCode(targetNation)),
          static_cast<int>(dispatchAmount), targetNation, 0, 0);
      return;
    }
  } else {
    unsigned short ledgerAmount =
        *reinterpret_cast<unsigned short*>(raw + 0x1e + targetNationSlot * 2);
    short* ledgerEntry = reinterpret_cast<short*>(raw + 0x1e + targetNationSlot * 2);
    if (static_cast<short>(ledgerAmount) < 1) {
      dispatchAmount = 0;
    } else if (static_cast<short>(ledgerAmount) < static_cast<short>(dispatchAmount)) {
      dispatchAmount = ledgerAmount;
    }
    short availableAmount =
        static_cast<short>(owner->GetEffectiveDiplomacyCounterA2ForCode(targetNation));
    if (availableAmount < static_cast<short>(dispatchAmount)) {
      dispatchAmount =
          static_cast<unsigned int>(owner->GetEffectiveDiplomacyCounterA2ForCode(targetNation));
    }
    *ledgerEntry = static_cast<short>(*ledgerEntry - static_cast<short>(dispatchAmount));
  }
  g_pNationInteractionStateManager->DispatchProposalAmountSlot60(
      owner->nationSlot, arg2, static_cast<int>(dispatchAmount), arg3, targetNation, 0, 0);
}

// FUNCTION: IMPERIALISM 0x0052fcc0
void TForeignMinister::RecomputeOrderStateSlot9C() {
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x12) = 0;
  *reinterpret_cast<short*>(raw + 0x14) = 0;
  *reinterpret_cast<short*>(raw + 0x10) = kPrimaryNationUnset;
  TGreatPower* owner = this->ownerContextAt04;
  if (owner->GetDiplomacyCounterA2() == 0) {
    *reinterpret_cast<short*>(raw + 0x18) =
        static_cast<short>(*reinterpret_cast<short*>(raw + 0x18) + 1);
  }
  unsigned int* block = reinterpret_cast<unsigned int*>(raw + 0x1e);
  for (int i = 0; i < 8; ++i) {
    block[i] = 0;
  }
  *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(block) + 0x20) = 0;
}

// FUNCTION: IMPERIALISM 0x0052fd10
void TForeignMinister::RefreshForeignMinisterStateByLocalizationMode() {
  if (g_pSimMgr->GetTurnTickSlot3C() == 1) {
    this->MinisterSlot18();
  }
  if (g_pSimMgr->GetTurnTickSlot3C() == 2) {
    this->MinisterSlot19();
  }
  this->MinisterSlot1B();
  this->QueueTurnEventHintActionsByNationMetricsAndCompatibility();
  this->UpdateNationInteractionEnableFlagsByTerrainAndRelation();
  this->MinisterSlot17();
}

// FUNCTION: IMPERIALISM 0x0052fd80
void TForeignMinister::MinisterSlot18() {}

// FUNCTION: IMPERIALISM 0x0052fda0
void TForeignMinister::MinisterSlot19() {}

// FUNCTION: IMPERIALISM 0x0052fdc0
void TForeignMinister::UpdateNationInteractionEnableFlagsByTerrainAndRelation() {
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
void TForeignMinister::MinisterSlot17() {}

// TODO: port the 1359-byte SEH turn-event-hint queuer body (unported stub for now).
// FUNCTION: IMPERIALISM 0x00530200
void TForeignMinister::QueueTurnEventHintActionsByNationMetricsAndCompatibility() {}

// FUNCTION: IMPERIALISM 0x005308b0
char TForeignMinister::EvaluateLocalizedScoreThresholdPredicateForNationValue(int nationCode) {
  // Two difficulty-indexed threshold rows (A = [difficulty], B = [difficulty + 5]).
  int thresholds[10] = {0x15, 0x12, 0xf, 0xd, 0xb, 0x1b, 0x17, 0x13, 0x10, 0xe};
  int difficulty = g_pSimMgr->redrawEnabled; // [g_pSimMgr + 0x40] scenario/difficulty index
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
void TForeignMinister::DispatchAction210ToFirstEligibleNationIfIdle() {
  // The original reloads the owning great power (this->ownerContextAt04) at each use
  // rather than caching it; access it inline so the same reload codegen is emitted.
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    if (this->ownerContextAt04->HasActiveCandidateNationSlots() !=
        0) {
      return;
    }
    if (nationSlot != this->ownerContextAt04->nationSlot &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationSlot) != 0 &&
        this->EvaluateLocalizedScoreThresholdPredicateForNationValue(nationSlot) != 0) {
      this->ownerContextAt04
          ->SetCandidateNationFlagAndPortZoneState(nationSlot);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00530bb0
void TForeignMinister::MinisterSlot1B() {}

// FUNCTION: IMPERIALISM 0x00530fa0
void TForeignMinister::ValidateProposalSelectionAndQueueEvent1C(short queueIndex) {
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
        gp->QueueInterNationEventForProposalCode12D_130(queueIndex);
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
    gp->ApplyAcceptedDiplomacyProposalCode(queueIndex);
    return;
  }
  gp->QueueInterNationEventForProposalCode12D_130(queueIndex);
}

// FUNCTION: IMPERIALISM 0x00531110
void TForeignMinister::Call80() {}
