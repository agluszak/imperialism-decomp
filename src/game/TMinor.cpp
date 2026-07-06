#include "game/TMinor.h"

#include "game/CIterator.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/nation_slot_eligibility.h"
#include "game/TCivUnit.h"
#include "game/TDiplomacyMgr.h"
#include "game/TTradeMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TGreatPower.h"
#include "game/TInterNationEventQueueManager.h"
#include "game/TMilitaryUnit.h"
#include "game/TStream.h"
#include "game/TTown.h"
#include "game/TUnit.h"
#include "game/nation_stream_serialization.h"

#include <new>

static const unsigned int kAddrClassDescTMinor = 0x006536a0;

namespace {

short DecodeTerrainNationSlotFromEncoded(short encodedNationSlot, short nationSlot) {
  if (encodedNationSlot < 200) {
    if (encodedNationSlot < 100) {
      return nationSlot;
    }
    return static_cast<short>(encodedNationSlot - 100);
  }
  return static_cast<short>(encodedNationSlot - 200);
}

void SwapAdjacentBytesInShortArray(short* entries, int pairCount) {
  for (int i = 0; i < pairCount; ++i) {
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&entries[i]);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
  }
}

int SignedDivideBy100(int value) {
  return value / 100;
}

} // namespace

extern undefined4 GenerateThreadLocalRandom15(void);

// SYNTHETIC: IMPERIALISM 0x004e3660
// TMinor::CreateObject
// SYNTHETIC: IMPERIALISM 0x004e36f0
// TMinor::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMinor, TCountry)

void* TMinor::GetTMinorClassNamePointer() {
  return reinterpret_cast<void*>(kAddrClassDescTMinor);
}

// FUNCTION: IMPERIALISM 0x004e3710
TMinor::TMinor() {
  encodedNationSlot = 0;
}

// SYNTHETIC: IMPERIALISM 0x004e3790
// TMinor::`scalar deleting destructor'
TMinor::~TMinor() {}

// FUNCTION: IMPERIALISM 0x004e41c0
void TMinor::ReadFrom(TStream* stream) {
  TCountry::ReadFrom(stream);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0x94, 0x2e);
  SwapAdjacentBytesInShortArray(this->needCurrentByType, 0x17);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0xc2, 0x2e);
  SwapAdjacentBytesInShortArray(this->diplomacyPolicyByNation, 0x17);
  stream->ReadBytes(reinterpret_cast<char*>(this) + 0xf0, 0x2e);
  SwapAdjacentBytesInShortArray(this->diplomacyGrantByNation, 0x17);
  stream->ReadBytes(&this->diplomacyRandomThreshold11e, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold120, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold122, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold124, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold126, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold128, 2);
  stream->ReadBytes(&this->diplomacyRandomThreshold12a, 2);
  stream->ReadBytes(&this->diplomacyPolicyPredicateCode12c, 2);
  stream->ReadBytes(&this->diplomacyPolicyPredicateCode12e, 2);
  stream->ReadBytes(&this->diplomacyPolicyGate130, 2);
  stream->ReadBytes(&this->diplomacyPolicyGate132, 2);
  stream->ReadBytes(diplomacySaveFields134, 8);
  SwapAdjacentBytesInShortArray(diplomacySaveFields134, 4);
  if (g_nSaveFormatVersion > 0x39) {
    stream->ReadBytes(diplomacySaveExt13c, 0x2e);
    SwapAdjacentBytesInShortArray(diplomacySaveExt13c, 0x17);
  }
}

// FUNCTION: IMPERIALISM 0x004e4390
void TMinor::WriteTo(TStream* stream) {
  TCountry::WriteTo(stream);
  WriteShortArrayElems(stream, this->needCurrentByType, 0x17);
  WriteShortArrayElems(stream, this->diplomacyPolicyByNation, 0x17);
  WriteShortArrayElems(stream, this->diplomacyGrantByNation, 0x17);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold11e, 2);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold120, 2);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold122, 2);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold124, 2);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold126, 2);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold128, 2);
  stream->WriteBytesSlot78(&this->diplomacyRandomThreshold12a, 2);
  stream->WriteBytesSlot78(&this->diplomacyPolicyPredicateCode12c, 2);
  stream->WriteBytesSlot78(&this->diplomacyPolicyPredicateCode12e, 2);
  stream->WriteBytesSlot78(&this->diplomacyPolicyGate130, 2);
  stream->WriteBytesSlot78(&this->diplomacyPolicyGate132, 2);
  WriteShortArrayElems(stream, diplomacySaveFields134, 4);
  WriteShortArrayElems(stream, diplomacySaveExt13c, 0x17);
}

// FUNCTION: IMPERIALISM 0x004e45f0
char TMinor::ReturnFalseNationStateCapabilityFlag90(int arg) {
  return (arg > 0xc && arg < 0x11) ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x004e4630
int TMinor::SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) {
  short sum = static_cast<short>(this->needCurrentByType[nationSlot] +
                                 this->diplomacyGrantByNation[nationSlot]);
  if (sum < 0) {
    sum = 0;
  }
  return sum;
}

// FUNCTION: IMPERIALISM 0x004e4660
short TMinor::GetDiplomacyExternalStateByTarget(short nationSlot) {
  return this->needCurrentByType[nationSlot];
}

// FUNCTION: IMPERIALISM 0x004e4680
short TMinor::QueryNationMetricBySlot7C(short metricSlot) {
  return this->diplomacyPolicyByNation[metricSlot];
}

// FUNCTION: IMPERIALISM 0x004e46a0
void TMinor::RebuildDiplomacyEconomicPressureFromMapState(void) {
  TGreatPower* nation = reinterpret_cast<TGreatPower*>(this);
  nation->needTargetByType[0x13] = -10;
  nation->needTargetByType[0x14] = 0;
  nation->needTargetByType[0x15] = 0;
  for (int i = 0; i < 0x17; ++i) {
    nation->needCurrentByType[i] = 0;
    nation->diplomacyPolicyByNation[i] = 0;
    nation->diplomacyGrantByNation[i] = 0;
    nation->relationDeltaCurrent[i] = 0;
    nation->relationDeltaSnapshot[i] = 0;
    nation->diplomacyState1c6[i] = 0;
    nation->diplomacyState1f4[i] = 0;
    nation->diplomacyState222[i] = 0;
    nation->diplomacyState250[i] = 0;
  }
  nation->diplomacyCounterA2 = 2;
}

// FUNCTION: IMPERIALISM 0x004e49b0
void TMinor::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                            int multiplier) {
  short resourceSlot = static_cast<short>(resourceIndex);
  short deltaShort = static_cast<short>(delta);

  if (deltaShort >= 1 && resourceSlot >= 0xd && resourceSlot <= 0x10) {
    if (resourceSlot == this->diplomacyPolicyPredicateCode12c) {
      this->diplomacyPolicyGate130 = deltaShort;
      return;
    }
    if (resourceSlot == this->diplomacyPolicyPredicateCode12e) {
      this->diplomacyPolicyGate132 = deltaShort;
      return;
    }
    return;
  }

  if (resourceSlot < 0 || resourceSlot > 6) {
    if (resourceSlot == 7) {
      this->diplomacyGrantByNation[7] =
          static_cast<short>(this->diplomacyGrantByNation[7] + deltaShort);
    }
    return;
  }

  this->diplomacyGrantByNation[resourceSlot] =
      static_cast<short>(this->diplomacyGrantByNation[resourceSlot] + deltaShort);
  if (this->recurringGrantByResource[resourceSlot] == 0) {
    return;
  }

  short needCurrent = this->needCurrentByType[resourceSlot];
  if (needCurrent == 0) {
    return;
  }

  for (int majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
    if (g_apTerrainTypeDescriptorTable[majorNationSlot] == 0) {
      continue;
    }
    short linkValue = this->relationGrantLinkMatrix[resourceSlot][majorNationSlot];
    if (linkValue == 0) {
      continue;
    }

    TGreatPower* majorNation = g_apNationStates[majorNationSlot];
    if (majorNation == 0) {
      continue;
    }

    short standing =
        g_pDiplomacyTurnStateManager
            ->relationStandingScoreMatrix79c[this->nationSlot * kNationSlotCount + majorNationSlot];
    int negDelta = -static_cast<int>(deltaShort);
    int intFactor = negDelta;
    if (negDelta < linkValue) {
      intFactor = linkValue;
    }

#if defined(_MSC_VER)
    float floatAmount = static_cast<float>(linkValue) / static_cast<float>(needCurrent);
    floatAmount = floatAmount * static_cast<float>(standing);
    floatAmount = floatAmount * static_cast<float>(multiplier);
    floatAmount = floatAmount * static_cast<float>(deltaShort);
    floatAmount = floatAmount * g_ApplyIndexedResourceDeltaScale_00653728;
    int amountFloat = static_cast<int>(floatAmount);
    int amountInt = SignedDivideBy100(intFactor * static_cast<int>(standing) * multiplier);
    int amount = amountFloat;
    if (amountInt > amount) {
      amount = amountInt;
    }
#else
    int amount = SignedDivideBy100(intFactor * static_cast<int>(standing) * multiplier);
#endif
    majorNation->AddAmountToAidAllocationMatrixCellAndTotal(amount, resourceSlot, this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e4bd0
void TMinor::SeedRandomDiplomacyPolicyThresholds(void) {
  short savedPredicate = this->diplomacyPolicyPredicateCode12c;
  short proposalWeight = 0;
  if (this == 0 || this->encodedNationSlot <= 99 || this->encodedNationSlot >= 200) {
    int randomBucket = static_cast<int>(GenerateThreadLocalRandom15()) % 100;
    int resourceType = 0;
    if (randomBucket < 0x19) {
      resourceType = 0;
    } else if (randomBucket < 0x32) {
      resourceType = 1;
    } else {
      resourceType = ((0x4a < randomBucket) - 1 & 0xfffffffb) + 7;
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceType);
    if (this->diplomacyRandomThreshold124 < proposalWeight) {
      this->diplomacyPolicyByNation[resourceType] = this->needCurrentByType[resourceType];
    }

    for (int policySlot = 0; policySlot < 8; ++policySlot) {
      proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(policySlot);
      if (this->diplomacyRandomThreshold122 < proposalWeight) {
        this->diplomacyPolicyByNation[policySlot] = this->needCurrentByType[policySlot];
      }
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(3);
    if (this->diplomacyRandomThreshold126 < proposalWeight) {
      this->diplomacyPolicyByNation[3] = this->needCurrentByType[3];
    } else if (this->recurringGrantByResource[3] != 0) {
      this->diplomacyPolicyByNation[3] = this->recurringGrantByResource[3];
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(4);
    if (this->diplomacyRandomThreshold128 < proposalWeight) {
      this->diplomacyPolicyByNation[4] = this->needCurrentByType[4];
    } else if (this->recurringGrantByResource[4] != 0) {
      this->diplomacyPolicyByNation[4] = this->recurringGrantByResource[4];
    }

    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(6);
    if (this->diplomacyRandomThreshold12a < proposalWeight) {
      this->diplomacyPolicyByNation[6] = this->needCurrentByType[6];
    } else if (this->recurringGrantByResource[6] != 0) {
      this->diplomacyPolicyByNation[6] = this->recurringGrantByResource[6];
    }

    if (this->diplomacyPolicyByNation[0] == 0) {
      this->diplomacyPolicyByNation[0] = this->recurringGrantByResource[0];
    }
    if (this->diplomacyPolicyByNation[1] == 0) {
      this->diplomacyPolicyByNation[1] = this->recurringGrantByResource[1];
    }
    if (this->diplomacyPolicyByNation[2] == 0) {
      this->diplomacyPolicyByNation[2] = this->recurringGrantByResource[2];
    }
  }

  if (savedPredicate == this->diplomacyPolicyPredicateCode12c) {
    short rolledPredicate = this->diplomacyPolicyPredicateCode12c;
    do {
      int roll = static_cast<int>(GenerateThreadLocalRandom15()) % 100;
      if (roll < 0x1e) {
        rolledPredicate = 0xd;
      } else if (roll < 0x3c) {
        rolledPredicate = 0xe;
      } else {
        rolledPredicate = static_cast<short>((0x59 < roll) + 0xf);
      }
    } while (rolledPredicate == this->diplomacyPolicyPredicateCode12c);
    proposalWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(rolledPredicate);
    if (this->diplomacyRandomThreshold11e < proposalWeight) {
      this->diplomacyPolicyPredicateCode12c = -10;
    } else {
      this->diplomacyPolicyPredicateCode12c = rolledPredicate;
    }
  }

  this->diplomacyPolicyPredicateCode12e = -10;
  int candidatePredicate = 0xd;
  do {
    proposalWeight =
        g_pNationInteractionStateManager->QueryProposalWeightSlot4C(candidatePredicate);
    if (proposalWeight < this->diplomacyRandomThreshold120 &&
        candidatePredicate != this->diplomacyPolicyPredicateCode12c) {
      this->diplomacyPolicyPredicateCode12e = static_cast<short>(candidatePredicate);
      candidatePredicate = 0x11;
    }
    candidatePredicate = candidatePredicate + 1;
  } while (candidatePredicate < 0x11);

  if (this->diplomacyPolicyPredicateCode12c != -10) {
    this->diplomacyPolicyByNation[this->diplomacyPolicyPredicateCode12c] = -1;
  }
  if (this->diplomacyPolicyPredicateCode12e != -10) {
    this->diplomacyPolicyByNation[this->diplomacyPolicyPredicateCode12e] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x004e4ee0
bool TMinor::IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short policyCode) {
  if (policyCode <= 0xc || policyCode >= 0x11) {
    return false;
  }
  if (policyCode == this->diplomacyPolicyPredicateCode12c) {
    return this->diplomacyPolicyGate130 == 0;
  }
  if (policyCode == this->diplomacyPolicyPredicateCode12e) {
    return this->diplomacyPolicyGate132 == 0;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x004e4f50
char TMinor::TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3, int arg4) {
  if (this->ReturnFalseNationStateCapabilityFlag90(arg4) == 0) {
    return 0;
  }

  g_pNationInteractionStateManager->DispatchProposalAmountSlot60(this->nationSlot, arg1, arg2, arg3,
                                                                 arg4, 1, 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e4fa0
void TMinor::ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) {
  short targetNationSlot = static_cast<short>(nationSlot);
  short policyValue = static_cast<short>(resetLevel);
  if (targetNationSlot != this->nationSlot) {
    if (policyValue != this->needLevelByNation[targetNationSlot]) {
      this->needLevelByNation[targetNationSlot] = policyValue;
      if (policyValue == 300) {
        this->ReassignUnitOrdersForCountryTargetChange(-1, 0);
      }
    }
  }
}

void TMinor::SetDiplomacyStandingSlot48(int targetNation, int standing) {
  this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(targetNation), standing);
}

char TMinor::HasMinorStandingLinkSlot5C(int sourceNation) {
  return this->IsEncodedNationSlotMinus200Equal(sourceNation);
}

void TMinor::ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode) {
  g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(sourceNation, this->nationSlot,
                                                              packedRelationCode, 0);
}

char TMinor::HasStandingPropagationBridgeSlot90(int targetNation) {
  if (targetNation < 0 || targetNation >= 7) {
    return 0;
  }
  for (int resourceType = 0; resourceType < 7; ++resourceType) {
    if (this->relationGrantLinkMatrix[resourceType][targetNation] != 0) {
      return 1;
    }
  }
  return 0;
}

void TMinor::NotifyNationAuxRuntimeFinalizeSlotC0(void) {
  for (int resourceType = 0; resourceType < 7; ++resourceType) {
    for (int majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
      this->relationGrantLinkMatrix[resourceType][majorNationSlot] = 0;
    }
  }
}

void TMinor::ClearNationAuxRuntimeGrantSlotC4(int grantValue) {
  if (grantValue == -1) {
    for (int resourceType = 0; resourceType < 0x17; ++resourceType) {
      this->recurringGrantByResource[resourceType] = 0;
    }
    return;
  }
  if (grantValue >= 0 && grantValue < 0x17) {
    this->recurringGrantByResource[grantValue] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004e4ff0
char TMinor::CanInitiateJoinEmpireProposalToTarget(short targetNationSlot, short proposalCode) {
  if (proposalCode != 0x12d || this->encodedNationSlot != -1) {
    return 0;
  }

  const int source = this->nationSlot;
  short standing =
      g_pDiplomacyTurnStateManager
          ->relationStandingScoreMatrix79c[source * kNationSlotCount + targetNationSlot];
  if (standing <= 0xf9) {
    return 0;
  }

  char canPropose = 1;
  short* peerStandingRow =
      &g_pDiplomacyTurnStateManager->relationStandingScoreMatrix79c[source * kNationSlotCount];
  for (int peerSlot = 0; peerSlot < 7; ++peerSlot) {
    if (peerSlot == targetNationSlot || g_apTerrainTypeDescriptorTable[peerSlot] == 0) {
      continue;
    }
    int delta = static_cast<int>(peerStandingRow[peerSlot]) - static_cast<int>(standing);
    if (delta < 0) {
      delta = -delta;
    }
    if (delta < 10) {
      canPropose = 0;
      break;
    }
  }
  return canPropose;
}

// FUNCTION: IMPERIALISM 0x004e50d0
void TMinor::QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) {
  short targetNation = static_cast<short>(targetNationId);
  if (proposalCode == 0x12d) {
    char canPropose = 0;
    if (this->encodedNationSlot == -1) {
      canPropose = this->CanInitiateJoinEmpireProposalToTarget(targetNation, proposalCode);
    }
    if (canPropose != 0) {
      if (g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(this->nationSlot, targetNation) ==
          0) {
        this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(targetNation), 1);
        g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(3, this->nationSlot,
                                                                            targetNation, 0);
        return;
      }
      if (g_apNationStates[targetNation] != 0) {
        g_apNationStates[targetNation]->QueueDiplomacyProposalCodeForTargetNation(0x132,
                                                                                  this->nationSlot);
      }
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(3, this->nationSlot,
                                                                          targetNation, 0);
      return;
    }
    if (g_apNationStates[targetNation] != 0) {
      g_apNationStates[targetNation]->NotifyActionSlot94(this->nationSlot,
                                                         -static_cast<int>(proposalCode));
    }
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(9, targetNation,
                                                                        this->nationSlot, 0);
    return;
  }

  if (proposalCode == 0x12f) {
    if (this->encodedNationSlot == -1) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNation, 3);
      if (g_apNationStates[targetNation] != 0) {
        g_apNationStates[targetNation]->NotifyActionSlot94(this->nationSlot, proposalCode);
      }
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(5, this->nationSlot,
                                                                          targetNation, 0);
    }
    return;
  }

  if (proposalCode == 0x130 && this->encodedNationSlot == -1) {
    g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, targetNation, 4);
    if (g_apNationStates[targetNation] != 0) {
      g_apNationStates[targetNation]->NotifyActionSlot94(this->nationSlot, proposalCode);
    }
    g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(2, this->nationSlot,
                                                                        targetNation, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004e5300
void TMinor::NotifyActionSlot94(int sourceNation, int actionCode) {
  (void)sourceNation;
  if (actionCode == 0x131) {
    this->ApplyDiplomacyRelationMaskToProvinceLinkedObjects(-1);
    this->QueueInterNationEvent17ForState300AffectedNations();
  }
}

// FUNCTION: IMPERIALISM 0x004e5340
void TMinor::SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) {
  this->SetNationRowDisplayValueByDiplomacyPredicate(static_cast<short>(targetNationSlot), 0);

  if (this->encodedNationSlot < 200) {
    this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);

    for (int eligibleNationSlot = 0; eligibleNationSlot < kNationSlotCount; ++eligibleNationSlot) {
      if (IsNationSlotEligibleForEventProcessing(static_cast<short>(eligibleNationSlot)) != 0 &&
          eligibleNationSlot != this->nationSlot && eligibleNationSlot != targetNationSlot) {
        TCountry* terrain = g_apTerrainTypeDescriptorTable[eligibleNationSlot];
        if (terrain != 0) {
          terrain->SetNationPercentFieldByModeAndDescriptorLinks(this->nationSlot, 100);
        }
      }
    }
    g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

    for (int majorNationSlot = 0; majorNationSlot < 7; ++majorNationSlot) {
      if (IsNationSlotEligibleForEventProcessing(static_cast<short>(majorNationSlot)) != 0) {
        TGreatPower* majorNation = g_apNationStates[majorNationSlot];
        if (majorNation != 0 && majorNation->diplomacyEligibilityA0 == 0) {
          majorNation->NotifyActionSlot94(this->nationSlot, 0x131);
        }
        g_pDiplomacyTurnStateManager->SetRelationCodeSlot74WithMode(this->nationSlot,
                                                                    majorNationSlot, 6, 0);
        g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, majorNationSlot,
                                                             0x31);
      }
    }

    for (int minorSlot = 7; minorSlot < kNationSlotCount; ++minorSlot) {
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, minorSlot, 0x6e);
    }
    return;
  }

  short decodedNationSlot =
      DecodeTerrainNationSlotFromEncoded(this->encodedNationSlot, this->nationSlot);

  TGreatPower* targetMajor = g_apNationStates[decodedNationSlot];
  if (targetMajor != 0) {
    targetMajor->NotifyActionSlot94(this->nationSlot, 0x13c);
  }
  g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x16, decodedNationSlot,
                                                                      this->nationSlot, 0);

  for (int resetNationSlot = 0; resetNationSlot < kNationSlotCount; ++resetNationSlot) {
    if (IsNationSlotEligibleForEventProcessing(static_cast<short>(resetNationSlot)) != 0) {
      g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, resetNationSlot,
                                                               4);
      g_pDiplomacyTurnStateManager->SetStandingScoreSlot28(this->nationSlot, resetNationSlot, 0x5a);
    }
  }

  short ownedRegionIds[10];
  for (int index = 0; index < 10; ++index) {
    ownedRegionIds[index] = -1;
  }

  if (this->ownedRegionList != 0) {
    int ownedCount = this->ownedRegionList->GetCount();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      short regionId = static_cast<short>(this->ownedRegionList->GetIntByOrdinal(oneBasedIndex));
      if (oneBasedIndex - 1 < 10) {
        ownedRegionIds[oneBasedIndex - 1] = regionId;
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetCount();
    }
  }

  if (g_pMapContextActionManager != 0) {
    for (int index = 0; index < 10; ++index) {
      int regionId = ownedRegionIds[index];
      if (regionId == -1) {
        continue;
      }
      short regionOwner = *reinterpret_cast<short*>(
          reinterpret_cast<unsigned char*>(g_pMapContextActionManager) + 0x1c + regionId * 2);
      if (regionOwner == this->nationSlot || regionOwner == decodedNationSlot) {
        g_pGlobalMapState->DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
            static_cast<short>(regionId), decodedNationSlot);
      }
    }
  }

  this->encodedNationSlot = static_cast<short>(targetNationSlot + 100);
  for (int linkNationSlot = 0; linkNationSlot < kNationSlotCount; ++linkNationSlot) {
    if (IsNationSlotEligibleForEventProcessing(static_cast<short>(linkNationSlot)) != 0 &&
        linkNationSlot != this->nationSlot && linkNationSlot != targetNationSlot) {
      TCountry* terrain = g_apTerrainTypeDescriptorTable[linkNationSlot];
      if (terrain != 0) {
        terrain->SetNationPercentFieldByModeAndDescriptorLinks(this->nationSlot, 100);
      }
    }
  }
  g_pDiplomacyTurnStateManager->ResetTerrainAdjacencyMatrixRowAndSymmetricLink(this->nationSlot);

  for (int standingNationSlot = 0; standingNationSlot < 7; ++standingNationSlot) {
    if (IsNationSlotEligibleForEventProcessing(static_cast<short>(standingNationSlot)) != 0) {
      if (standingNationSlot == targetNationSlot) {
        this->SetDiplomacyStandingSlot48(standingNationSlot, 100);
        if (g_apNationStates[standingNationSlot] != 0) {
          g_apNationStates[standingNationSlot]->ResetDiplomacyLevelForNationSlot12(this->nationSlot,
                                                                                   100);
          g_apNationStates[standingNationSlot]->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(
              this->nationSlot, static_cast<unsigned short>(-1));
        }
      } else {
        this->SetDiplomacyStandingSlot48(standingNationSlot, 300);
        if (g_apNationStates[standingNationSlot] != 0) {
          g_apNationStates[standingNationSlot]->ResetDiplomacyLevelForNationSlot12(this->nationSlot,
                                                                                   300);
        }
      }
    }
  }

  this->QueueInterNationEvent17ForState300AffectedNations();
  if (g_apNationStates[targetNationSlot] != 0 &&
      reinterpret_cast<unsigned char*>(g_apNationStates[targetNationSlot])[0x8ce] < 3) {
    g_apNationStates[targetNationSlot]->SetNationPendingActionStateAndPayload(6, this->nationSlot);
  }
}

// FUNCTION: IMPERIALISM 0x004e5730
void TMinor::HandleNetworkPortConstructionOrder(int nationId) {
  char* terrainTileBytes =
      *reinterpret_cast<char**>(reinterpret_cast<unsigned char*>(g_pGlobalMapState) + 0xc);
  unsigned char nationTileFlags =
      terrainTileBytes[0x1c + static_cast<short>(this->ownerNationSlot) * 0x24];
  if ((nationTileFlags >> 2 & 1) != 0) {
    return;
  }

  TTown* marker = new TTown();
  marker->InitializeTownMarker("", this->ownerNationSlot, 1, static_cast<short>(nationId));
  marker->activeFlag4f = 1;
  g_pGlobalMapState->SetTileTransportFlags(this->ownerNationSlot, 0x15);
  TGreatPower* targetNation = g_apNationStates[nationId];
  if (targetNation != 0 && targetNation->townMarkerList != 0) {
    targetNation->townMarkerList->AddTail(marker);
  }
}

// FUNCTION: IMPERIALISM 0x004e5840
void TMinor::ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) {
  TCountry::ApplyJoinEmpireMode1TargetTransition(targetNationSlot);
  g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x1b, this->nationSlot,
                                                                      targetNationSlot, 0);
}

// FUNCTION: IMPERIALISM 0x004e59d0
void TMinor::ApplyJoinEmpireMode2FinalizeNationNameState(void) {
  short decodedSlot = DecodeTerrainNationSlotFromEncoded(this->encodedNationSlot, this->nationSlot);
  this->encodedNationSlot = -1;
  this->SetNationRowDisplayValueByDiplomacyPredicate(decodedSlot, 0);
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    this->SetDiplomacyStandingSlot48(nationSlot, 100);
  }
}

// FUNCTION: IMPERIALISM 0x004e5a40
void TMinor::SetNationRowDisplayValueByDiplomacyPredicate(short targetNationSlot,
                                                          short predicateCode) {
  (void)predicateCode;
  for (int nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(targetNationSlot, nationSlot) ==
            0 &&
        (nationSlot == this->nationSlot ||
         (g_apNationStates[targetNationSlot] != 0 &&
          reinterpret_cast<unsigned char*>(
              g_apNationStates[targetNationSlot])[0x918 + nationSlot] == 0))) {
      this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(nationSlot), 100);
    } else {
      this->ResetDiplomacyLevelForNationSlot12(static_cast<NationSlot>(nationSlot), 300);
    }
  }
}

namespace {

void DispatchCivilianOrderRelationMaskSlots(TUnit* orderNode) {
  if (orderNode->orderType == 7) {
    TGreatPower* ownerNation = g_apNationStates[orderNode->field_18];
    if (ownerNation != 0) {
      short payload =
          *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(ownerNation) + 0x88);
      orderNode->VTableSlot10(static_cast<int>(payload));
    }
    return;
  }
  orderNode->DetachUnitOrderFromOwnerAndReset();
  orderNode->VTableSlot10(-1);
}

void WalkTileCivilianOrdersForRelationMask(TTerrainStateRecordView* terrainTiles, short tileId,
                                           const char* relationMaskByNation) {
  TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder20;
  while (orderNode != 0) {
    TUnit* nextNode = orderNode->nextOnTile;
    if (relationMaskByNation[orderNode->field_18] != 0) {
      DispatchCivilianOrderRelationMaskSlots(orderNode);
    }
    orderNode = nextNode;
  }
}

int ResolveDiplomacyMaskOwnerNationSlot(const TMinor* minor, short provinceId) {
  if (provinceId != -1) {
    return g_pGlobalMapState->cityScoreTable[provinceId].ownerNationCode00;
  }
  return DecodeTerrainNationSlotFromEncoded(minor->encodedNationSlot, minor->nationSlot);
}

} // namespace

// FUNCTION: IMPERIALISM 0x004e5ac0
void TMinor::ClearTileActivityOverlayByProvinceId(int provinceId) {
  char* tileArrayBase = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
  if (provinceId == -1) {
    if (this->ownedRegionList == 0) {
      return;
    }
    int ownedCount = this->ownedRegionList->GetCount();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->GetIntByOrdinal(oneBasedIndex);
      TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          short tileId = regionRecord->linkedRegionIds[linkedIndex];
          tileArrayBase[0x18 + tileId * 0x24] = static_cast<char>(-1);
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetCount();
    }
    return;
  }

  TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      short tileId = regionRecord->linkedRegionIds[linkedIndex];
      tileArrayBase[0x18 + tileId * 0x24] = static_cast<char>(-1);
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5be0
void TMinor::QueueInterNationEvent17ForState300AffectedNations(void) {
  int majorSlot;
  char needLevel300ByMajorSlot[7];
  for (majorSlot = 0; majorSlot < 7; ++majorSlot) {
    needLevel300ByMajorSlot[majorSlot] = (this->needLevelByNation[majorSlot + 1] == 300) ? 1 : 0;
  }

  char notifyMajorSlots[7] = {0};
  TTerrainStateRecordView* terrainTiles = g_pGlobalMapState->terrainStateTable;
  char* terrainBytes = reinterpret_cast<char*>(terrainTiles);

  if (this->ownedRegionList != 0) {
    int ownedCount = this->ownedRegionList->GetCount();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->GetIntByOrdinal(oneBasedIndex);
      TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          short tileId = regionRecord->linkedRegionIds[linkedIndex];
          int tileNation = static_cast<signed char>(terrainBytes[0x18 + tileId * 0x24]);
          if (tileNation != -1 && needLevel300ByMajorSlot[tileNation] != 0) {
            notifyMajorSlots[tileNation] = 1;
            terrainBytes[0x18 + tileId * 0x24] = static_cast<char>(-1);
          }
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetCount();
    }
  }

  for (majorSlot = 0; majorSlot < 7; ++majorSlot) {
    if (g_apNationStates[majorSlot] != 0 && notifyMajorSlots[majorSlot] != 0) {
      g_apNationStates[majorSlot]->NotifyActionSlot94(this->nationSlot, 0x137);
      g_pInterNationEventQueueManager->QueueInterNationEventRecordDeduped(0x17, majorSlot,
                                                                          this->nationSlot, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e5d90
void TMinor::ApplyDiplomacyRelationMaskToProvinceLinkedObjects(short provinceId) {
  const int ownerNationSlot = ResolveDiplomacyMaskOwnerNationSlot(this, provinceId);

  char relationMaskByNation[kTerrainTypeDescriptorTableCount];
  for (int nationSlot = 0; nationSlot < kTerrainTypeDescriptorTableCount; ++nationSlot) {
    relationMaskByNation[nationSlot] = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 && nationSlot != ownerNationSlot &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(ownerNationSlot, nationSlot) != 0) {
      relationMaskByNation[nationSlot] = 1;
    }
  }

  TTerrainStateRecordView* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId == -1) {
    if (this->ownedRegionList == 0) {
      return;
    }
    int ownedCount = this->ownedRegionList->GetCount();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->GetIntByOrdinal(oneBasedIndex);
      TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          WalkTileCivilianOrdersForRelationMask(
              terrainTiles, regionRecord->linkedRegionIds[linkedIndex], relationMaskByNation);
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetCount();
    }
    return;
  }

  TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      WalkTileCivilianOrdersForRelationMask(
          terrainTiles, regionRecord->linkedRegionIds[linkedIndex], relationMaskByNation);
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e6040
void TMinor::ReassignTileObjectOwnerAndNotifyForSelectedCells(int priorOwnerNationSlot) {
  TSortedList* destinationManager =
      g_apTerrainTypeDescriptorTable[priorOwnerNationSlot]->militaryUnitList44;
  if (this->ownedRegionList == 0 || destinationManager == 0 || this->militaryUnitList44 == 0) {
    return;
  }

  int ownedCount = this->ownedRegionList->GetCount();
  int oneBasedIndex = 1;
  while (oneBasedIndex <= ownedCount) {
    short regionId = static_cast<short>(this->ownedRegionList->GetIntByOrdinal(oneBasedIndex));
    if (regionId < 0 || regionId >= 0x180) {
      oneBasedIndex++;
      continue;
    }
    TMilitaryUnit* unitNode = g_pGlobalMapState->cityScoreTable[regionId].stationedUnitChain98;
    while (unitNode != 0) {
      TUnit* unit = unitNode;
      TMilitaryUnit* nextNode = static_cast<TMilitaryUnit*>(unitNode->nextOnTile);
      if (unit->field_18 == priorOwnerNationSlot) {
        unit->field_18 = this->nationSlot;
        CPtrList* sourceList = &this->militaryUnitList44->listState;
        POSITION pos = sourceList->Find(unit, 0);
        if (pos != 0) {
          sourceList->RemoveAt(pos);
        }
        destinationManager->AddTail(unit);
      }
      unitNode = nextNode;
    }
    oneBasedIndex++;
    ownedCount = this->ownedRegionList->GetCount();
  }
}

namespace {

void RetargetUnitOrderForAllowedNation(TUnit* orderNode) {
  short ownerNationSlot = orderNode->field_18;
  TGreatPower* ownerNation = g_apNationStates[ownerNationSlot];
  if (ownerNation == 0) {
    return;
  }
  short homeRegionIndex =
      *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(ownerNation) + 0x88);
  short spawnTile =
      g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(homeRegionIndex, 0);
  if (spawnTile == -1) {
    orderNode->DetachUnitOrderFromOwnerAndReset();
    orderNode->Free();
    return;
  }
  orderNode->VTableSlot10(static_cast<int>(spawnTile));
}

void RetargetUnitOrderForAllowedNationWithModeReset(TUnit* orderNode) {
  short ownerNationSlot = orderNode->field_18;
  TGreatPower* ownerNation = g_apNationStates[ownerNationSlot];
  if (ownerNation == 0) {
    return;
  }
  short homeRegionIndex =
      *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(ownerNation) + 0x88);
  short spawnTile =
      g_pGlobalMapState->FindReachableRecruitSpawnTileWithVisitedReset(homeRegionIndex, 0);
  if (spawnTile == -1) {
    orderNode->DetachUnitOrderFromOwnerAndReset();
    orderNode->Free();
    return;
  }
  orderNode->SetOrderModeSlot34(0, -1);
  orderNode->VTableSlot10(static_cast<int>(spawnTile));
}

void WalkTileUnitOrdersForRelationMask(TTerrainStateRecordView* terrainTiles, short tileId,
                                       const char* relationMaskByNation, char resetOrderMode) {
  TUnit* orderNode = terrainTiles[tileId].firstCivilianOrder20;
  while (orderNode != 0) {
    TUnit* nextNode = orderNode->nextOnTile;
    if (relationMaskByNation[orderNode->field_18] != 0) {
      if (resetOrderMode != 0) {
        RetargetUnitOrderForAllowedNationWithModeReset(orderNode);
      } else {
        RetargetUnitOrderForAllowedNation(orderNode);
      }
    }
    orderNode = nextNode;
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x004e6150
void TMinor::ReassignUnitOrdersForCountryTargetChange(short provinceId,
                                                      char includeAllPolicyTargets) {
  if (includeAllPolicyTargets == 0) {
    this->QueueInterNationEvent17ForState300AffectedNations();
  }

  int ownerNationSlot;
  if (provinceId == -1) {
    ownerNationSlot = DecodeTerrainNationSlotFromEncoded(this->encodedNationSlot, this->nationSlot);
  } else {
    ownerNationSlot = g_pGlobalMapState->cityScoreTable[provinceId].ownerNationCode00;
  }

  char relationMaskByNation[kTerrainTypeDescriptorTableCount];
  for (int nationSlot = 0; nationSlot < kTerrainTypeDescriptorTableCount; ++nationSlot) {
    relationMaskByNation[nationSlot] = 0;
    if (g_apTerrainTypeDescriptorTable[nationSlot] != 0 && nationSlot != ownerNationSlot &&
        (includeAllPolicyTargets != 0 || g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                                             this->nationSlot, nationSlot) != 0)) {
      relationMaskByNation[nationSlot] = 1;
    }
  }

  TTerrainStateRecordView* terrainTiles = g_pGlobalMapState->terrainStateTable;
  if (provinceId == -1) {
    if (this->ownedRegionList == 0) {
      return;
    }
    int ownedCount = this->ownedRegionList->GetCount();
    int oneBasedIndex = 1;
    while (oneBasedIndex <= ownedCount) {
      int regionId = this->ownedRegionList->GetIntByOrdinal(oneBasedIndex);
      TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[regionId];
      if (regionRecord->linkedRegionCount > 0) {
        int linkedIndex = 0;
        while (linkedIndex < regionRecord->linkedRegionCount) {
          WalkTileUnitOrdersForRelationMask(
              terrainTiles, regionRecord->linkedRegionIds[linkedIndex], relationMaskByNation, 0);
          linkedIndex++;
        }
      }
      oneBasedIndex++;
      ownedCount = this->ownedRegionList->GetCount();
    }
    return;
  }

  TGlobalMapCityScoreRecord* regionRecord = &g_pGlobalMapState->cityScoreTable[provinceId];
  if (regionRecord->linkedRegionCount > 0) {
    int linkedIndex = 0;
    while (linkedIndex < regionRecord->linkedRegionCount) {
      WalkTileUnitOrdersForRelationMask(terrainTiles, regionRecord->linkedRegionIds[linkedIndex],
                                        relationMaskByNation, 1);
      linkedIndex++;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e64a0
void TMinor::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->AddTailEx(reinterpret_cast<void*>(regionId));
  }
  this->ClearTileActivityOverlayByProvinceId(regionId);
  this->ApplyDiplomacyRelationMaskToProvinceLinkedObjects(regionId);
  this->ReassignUnitOrdersForCountryTargetChange(static_cast<short>(regionId), 1);
}

// FUNCTION: IMPERIALISM 0x004e64f0
void TMinor::AddRegionIdToNationOwnedRegionList(int regionId) {
  if (this->ownedRegionList != 0) {
    this->ownedRegionList->AddHead(reinterpret_cast<void*>(regionId));
  }
}

// FUNCTION: IMPERIALISM 0x004e6520
void TMinor::RelinkTileUnitsToCountryOrderManager(int destinationNationSlot) {
  TSortedList* destinationManager =
      g_apTerrainTypeDescriptorTable[destinationNationSlot]->militaryUnitList44;
  if (destinationManager == 0 || this->militaryUnitList44 == 0) {
    return;
  }

  CIterator unitCursor(this->militaryUnitList44);
  TUnit* unit = static_cast<TUnit*>(unitCursor.Reset());
  while (unitCursor.More() != 0) {
    unit->field_18 = static_cast<short>(destinationNationSlot);
    CPtrList* sourceList = &this->militaryUnitList44->listState;
    POSITION pos = sourceList->Find(unit, 0);
    if (pos != 0) {
      sourceList->RemoveAt(pos);
    }
    destinationManager->AddTail(unit);
    unit = static_cast<TUnit*>(unitCursor.Advance());
  }
}
