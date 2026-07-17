#include "decomp_types.h"
#include <stdlib.h>

#include "game/TAutoGreatPower.h"

#include "game/TOcean.h"
#include "game/TSortedByRelationshipList.h"
#include "game/nation_stream_serialization.h"
#include "game/CIterator.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TSortedList.h"
#include "game/nation_slot_eligibility.h"
#include "game/TSimMgr.h"
#include "game/TMinister.h"
#include "game/TForeignMinister.h"
#include "game/TCityInteriorMinister.h"
#include "game/TDefenseMinister.h"
#include "game/TStream.h"
#include "game/TMission.h"
#include "game/TMinor.h"
#include "game/TSortedList.h"
#include "game/TCity.h"
#include "game/global_data_tables.h"
#include "game/TZone.h"
#include <new>

#include "game/TMultiplayerMgr.h"
#include "game/TShip.h"

extern "C" int __cdecl rand(void);

// kNationSlotCount (0x17) comes from TDiplomacyMgr.h.
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const int kMapNodeCount = 0x180;
static const int kPortZoneCount = 0x70;

undefined4 PopulateCase16AdvisoryMapNodeCandidateState(void);

// FUNCTION: IMPERIALISM 0x004e6b10
void TAutoGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {}

// SYNTHETIC: IMPERIALISM 0x004e6a70
// TAutoGreatPower::CreateObject

// SYNTHETIC: IMPERIALISM 0x004e6b30
// TAutoGreatPower::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAutoGreatPower, TGreatPower)

// FUNCTION: IMPERIALISM 0x004e6b50
TAutoGreatPower::TAutoGreatPower() : TGreatPower() {
  missionQueue = 0;
}

// SYNTHETIC: IMPERIALISM 0x004e6b80
// TAutoGreatPower::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x004e6bb0
// TAutoGreatPower::~TAutoGreatPower

// FUNCTION: IMPERIALISM 0x004e7230
void TAutoGreatPower::Free(void) {
  if (this->missionQueue != 0) {
    int ordinal = this->missionQueue->GetCount();
    for (; ordinal > 0; --ordinal) {
      TMission* entry = static_cast<TMission*>(this->missionQueue->GetEntryByOrdinal(ordinal));
      // Vtable index 3 (byte offset 0xc): the real, inherited CObject::AssertValid()
      // (zero-arg MFC diagnostic check) -- TMission does not override it. Confirmed
      // against the assembly at 0x004e725d: `mov ecx,edi / call [ebx+0xc]`, no pushed args.
      entry->AssertValid();
      this->missionQueue->RemoveAtOrdinal(ordinal);
      entry->Free();
    }
    if (this->missionQueue != 0) {
      this->missionQueue->FreePayloadsAndDestroy();
    }
    this->missionQueue = 0;
  }
  TGreatPower::Free();
}

// FUNCTION: IMPERIALISM 0x004e72c0
void TAutoGreatPower::ReadFrom(TStream* stream) {
  TGreatPower::ReadFrom(stream);
  stream->ReadBytes(this->actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(this->actionMetricByQuarter, 6);

  stream->ReadBytes(this->mapNodeStateFlags, 0x180);
  stream->ReadBytes(this->portZoneStateFlags, 0x70);

  TSortedList* missionQueue = this->missionQueue;
  if (missionQueue->GetCount() != 0) {
    missionQueue->FreePayloads();
  }
  missionQueue->ReadFrom(stream);

  int missionContext = 0;
  stream->ReadBytes(&missionContext, 4);
  for (int queueIndex = 1; queueIndex < 0x71; ++queueIndex) {
    missionContext = 0;
    char hasMission = stream->ReadByte(&missionContext);
    if (hasMission != 0) {
      missionQueue->AddTailInt(missionContext);
    }
  }

  if (g_nSaveFormatVersion < 0x39) {
    this->QueueMapActionMissionFromCandidateAndMarkState(kMissionTypeScatteredShips, -1, 0, -1);
  }
}

// FUNCTION: IMPERIALISM 0x004e73f0
void TAutoGreatPower::WriteTo(TStream* stream) {
  TGreatPower::WriteTo(stream);

  WriteShortArrayElems(stream, this->actionMetricByQuarter, 6);

  stream->WriteBytesSlot78(this->mapNodeStateFlags, 0x180);
  stream->WriteBytesSlot78(this->portZoneStateFlags, 0x70);

  TSortedList* missionQueue = this->missionQueue;
  missionQueue->WriteTo(stream);
  int missionQueueCount = missionQueue->GetCount();

  int zeroWord = 0;
  stream->WriteBytesSlot78(&zeroWord, 4);
  int index = 1;
  if (index <= missionQueueCount) {
    do {
      stream->WriteObjectSlotB4(missionQueue->GetEntryByOrdinal(index), 0);
      ++index;
    } while (index <= missionQueueCount);
  }
}

// FUNCTION: IMPERIALISM 0x004e7510
void TAutoGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
  if (g_pSimMgr->redrawEnabled != 0) {
    g_pGameFlowState->DispatchTaggedGameStateEvent1F20(0x6c6f7374, this->nationSlot, -3);
  }
}

// FUNCTION: IMPERIALISM 0x004e7550
void TAutoGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) {
  if (this->city != 0) {
    this->RebuildNationResourceYieldCountersAndDevelopmentTargets();
    this->AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents();
  }
}

// FUNCTION: IMPERIALISM 0x004e7590
void TAutoGreatPower::OrphanRetStub_004dcc30(void) {
  if (this->city != 0) {
    this->interiorMinister->Call54();
  }
}

// FUNCTION: IMPERIALISM 0x004e75c0
undefined TAutoGreatPower::OrphanCallChain_C4_I28_004e75c0(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e7630
void TAutoGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                     int multiplier) {
  if (delta < 0 && resourceIndex > 6 && resourceIndex < 0x0D) {
    this->needCurrentByType[resourceIndex] =
        static_cast<short>(this->needCurrentByType[resourceIndex] + delta);
  }

  TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(resourceIndex, delta, multiplier);
}

// FUNCTION: IMPERIALISM 0x004e7680
void TAutoGreatPower::AssignNeedSlotFromSourceSlot19C(short needSlot, short sourceNation) {
  if (g_apNationStates[static_cast<short>(sourceNation)]->diplomacyEligibilityA0 != 0) {
    if (static_cast<short>(needSlot) != 5) {
      short relationScore = g_pDiplomacyTurnStateManager
                                ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 +
                                                                 static_cast<short>(sourceNation)];
      double scaledScore = static_cast<double>(relationScore) * g_DAT_00653fc0_Value_00653FC0;
      int roll = rand();
      if (static_cast<double>(roll) > scaledScore * g_DAT_00653fc8_Value_00653FC8) {
        this->OrphanCallChain_C4_I28_004e75c0(needSlot);
      }
      return;
    }
  } else if (static_cast<short>(needSlot) != 5) {
    short metricCap = 10;
    if (this->GetDiplomacyExternalStateByTarget(static_cast<short>(needSlot)) < 10) {
      metricCap = this->GetDiplomacyExternalStateByTarget(static_cast<short>(needSlot));
    }
    if (this->tradeCapacity < metricCap) {
      metricCap = this->tradeCapacity;
    }
    if (this->QueryNationMetricBySlot7C(static_cast<short>(needSlot)) == -1) {
      return;
    }
    this->SetDiplomacyState1c6ClampedToCounterA4(static_cast<short>(needSlot), metricCap);
    return;
  }
  if (this->GetDiplomacyExternalStateByTarget(5) != 0 && this->QueryNationMetricBySlot7C(5) != -1) {
    short metric = this->GetDiplomacyExternalStateByTarget(5);
    int assignAmount = (metric != 1) + 1;
    if (this->tradeCapacity < static_cast<short>(assignAmount)) {
      assignAmount = this->tradeCapacity;
    }
    this->SetDiplomacyState1c6ClampedToCounterA4(5, static_cast<short>(assignAmount));
  }
}

// FUNCTION: IMPERIALISM 0x004e7810
void TAutoGreatPower::ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  int total = 0;
  for (int resourceType = 0; static_cast<short>(resourceType) < 0x0E; ++resourceType) {
    short resourceWeight = GetResourceDescriptorWeightWord0ByType(static_cast<short>(resourceType));
    short orderCount = this->city->orderCountByType5c[resourceType];
    total += static_cast<short>(resourceWeight * orderCount);
  }

  this->tradeCapacity = static_cast<short>(total);
  this->diplomacyCounterA2 = static_cast<short>(total);
  this->diplomacyCounterB0 = 0;
  this->budgetPoolDelta = 0;
  this->budgetPoolBase = 0;

  for (int nationIndex = 0; nationIndex < kNationSlotCount; ++nationIndex) {
    this->diplomacyState1c6[nationIndex] = 0;
    for (int rowIndex = 0; rowIndex < kAidAllocationRowCount; ++rowIndex) {
      this->aidAllocationMatrix[rowIndex * kAidAllocationColumnCount + nationIndex] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e78d0
void TAutoGreatPower::RunSlot4CThenSortTrackedOrders(void) {
  static_cast<TCityInteriorMinister*>(this->interiorMinister)->CallD4();
}

// FUNCTION: IMPERIALISM 0x004e78f0
void TAutoGreatPower::ResetField900FromNeedCapA6(void) {
  this->defenseMinister->Call4C();
}

// FUNCTION: IMPERIALISM 0x004e7910
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message) {
  (void)message;
}

// FUNCTION: IMPERIALISM 0x004e7930
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message) {
  (void)message;
}

// FUNCTION: IMPERIALISM 0x004e7950
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message) {
  (void)message;
}

// FUNCTION: IMPERIALISM 0x004e7970
void TAutoGreatPower::SnapshotDiplomacyState1c6Into250(void) {}

// FUNCTION: IMPERIALISM 0x004e7990
void TAutoGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  this->foreignMinister->Call90();
  this->foreignMinister->Call94();
}

// FUNCTION: IMPERIALISM 0x004e79d0
char TAutoGreatPower::TryDispatchNationActionViaUiContextOrFallback(int targetNation, int arg2,
                                                                    int arg3, int slotIndex) {
  if (this->IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(static_cast<short>(slotIndex)) !=
      0) {
    this->foreignMinister->DispatchProposalSlot98(targetNation, arg2, arg3, slotIndex);
    return 0;
  }
  this->AppendTrackedSlotEntry(1, targetNation, 0, static_cast<short>(slotIndex), 0);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e7a50
void TAutoGreatPower::ClearDiplomacyState1c6Block(void) {
  if (this->city != 0) {
    this->foreignMinister->RecomputeOrderStateSlot9C();
    short* pendingMetric = this->actionMetricByQuarter;
    for (short needSlot = 7; needSlot < 0x0d; ++needSlot) {
      short pending = *pendingMetric;
      if (pending > 0) {
        short current = this->GetDiplomacyExternalStateByTarget(needSlot);
        short remaining;
        if (current < pending) {
          remaining = 0;
        } else {
          remaining = static_cast<short>(current - pending);
        }
        this->SetCityStockCounterAndRefresh(needSlot, remaining);
      }
      *pendingMetric = 0;
      ++pendingMetric;
    }
    TGreatPower::ClearDiplomacyState1c6Block();
  }
}

// FUNCTION: IMPERIALISM 0x004e7af0
void TAutoGreatPower::BeginTurnDiplomacyPrePassSlot1c8() {
  if (this->city != 0) {
    this->foreignMinister->RefreshForeignMinisterStateByLocalizationMode();
  }
}

// FUNCTION: IMPERIALISM 0x004e7b20
bool TAutoGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                                       short policyCode) {
  return TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(targetClass, policyCode);
}

// FUNCTION: IMPERIALISM 0x004e7b50
void TAutoGreatPower::QueueDiplomacyProposalCodeForTargetNation(short proposalCode,
                                                                short targetNationId) {
  switch (proposalCode) {
  case 0x12D:
  case 0x12F:
    return;
  case 0x12E:
  case 0x132: {
    if (g_pDiplomacyTurnStateManager != 0) {
      char hasAllianceGuard =
          g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(targetNationId, this->nationSlot);
      if (hasAllianceGuard == 0) {
        TGreatPower::QueueDiplomacyProposalCodeForTargetNation(proposalCode, targetNationId);
      }
    }
    return;
  }
  default:
    TGreatPower::QueueDiplomacyProposalCodeForTargetNation(proposalCode, targetNationId);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004e7be0
void TAutoGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  if (this->city == 0) {
    return;
  }

  int rowIndex = 1;
  if (this->proposalQueue->GetSize() >= rowIndex) {
    do {
      this->foreignMinister->ValidateProposalSelectionAndQueueEvent1C(static_cast<short>(rowIndex));
      ++rowIndex;
    } while (rowIndex <= this->proposalQueue->GetSize());
  }

  this->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

// FUNCTION: IMPERIALISM 0x004e7c50
void TAutoGreatPower::NotifyActionSlot94(int sourceNation, int actionCode) {
  if (actionCode == 0x131) {
    this->SetCandidateNationFlagAndPortZoneState(static_cast<short>(sourceNation));
  }
  TGreatPower::NotifyActionSlot94(sourceNation, actionCode);
}

// FUNCTION: IMPERIALISM 0x004e7ca0
void TAutoGreatPower::DispatchTurnEvent2103WithNationFromRecord() {}

// FUNCTION: IMPERIALISM 0x004e7cc0
int TAutoGreatPower::CheckTransitionSlot27C(int targetNation, int sourceNation) {
  char allBeatable = 1;
  char beatableByNation[7] = {0, 0, 0, 0, 0, 0, 0};
  int nation = 0;
  do {
    if (nation > 6) {
      break;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nation) != 0 &&
        nation != static_cast<short>(this->nationSlot)) {
      if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, nation) == 0 &&
          g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(targetNation, nation) != 0) {
        char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(
            targetNation, static_cast<int>(static_cast<short>(this->nationSlot)));
        float ratioScore;
        float standingScore;
        if (borderLinked != 0) {
          ratioScore = this->ComputeArmyScoreRatioVsNationWithSecondary(sourceNation, targetNation);
          standingScore =
              this->ComputeArmyScoreStandingRatioVsNationPair(sourceNation, targetNation);
        } else {
          ratioScore = this->ComputeNavyScoreRatioVsNationWithSecondary(sourceNation, targetNation);
          standingScore =
              this->ComputeNavyScoreStandingRatioVsNationPair(sourceNation, targetNation);
        }
        float combinedScore = ratioScore + standingScore;
        if (this->ComputeMinisterSkillFloatSlot88() <= combinedScore) {
          beatableByNation[nation] = 1;
        } else {
          allBeatable = 0;
        }
      }
    }
    ++nation;
  } while (allBeatable != 0);
  if (allBeatable != 0) {
    for (int helperNation = 0; helperNation < 7; ++helperNation) {
      if (beatableByNation[helperNation] != 0) {
        this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(helperNation, 1, targetNation);
      }
    }
    TMinor* minor = g_apSecondaryNationStateSlots[targetNation];
    short ownerSlot = minor->encodedNationSlot;
    if (ownerSlot < 200) {
      if (ownerSlot < 100) {
        ownerSlot = minor->nationSlot;
      } else {
        ownerSlot = static_cast<short>(ownerSlot - 100);
      }
    } else {
      ownerSlot = static_cast<short>(ownerSlot - 200);
    }
    if (ownerSlot != this->nationSlot) {
      minor->ApplyJoinEmpireModeForTargetNation(this->nationSlot, 1);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e7ec0
int TAutoGreatPower::PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) {
  char hasPolicy = 0;
  if (static_cast<char>(mode) == 0) {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, sourceNation) !=
        0) {
      hasPolicy = 1;
    }
  } else {
    if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, targetNation) !=
        0) {
      hasPolicy = 1;
    }
  }
  if (hasPolicy == 0) {
    char borderLinked = g_pGlobalMapState->AreNationsBorderLinked(
        sourceNation, static_cast<int>(static_cast<short>(this->nationSlot)));
    float ratioScore;
    float standingScore;
    if (borderLinked != 0) {
      ratioScore = this->ComputeArmyScoreRatioForNationPair(sourceNation, targetNation,
                                                            static_cast<char>(mode));
      standingScore = this->ComputeArmyScoreStandingRatioForNationPair(sourceNation, targetNation,
                                                                       static_cast<char>(mode));
    } else {
      ratioScore = this->ComputeNavyScoreRatioForNationPair(sourceNation, targetNation,
                                                            static_cast<char>(mode));
      standingScore = this->ComputeNavyScoreStandingRatioForNationPair(sourceNation, targetNation,
                                                                       static_cast<char>(mode));
    }
    float combinedScore = standingScore + ratioScore;
    if (this->ComputeMinisterSkillFloatSlot88() <= combinedScore) {
      if (static_cast<char>(mode) == 0) {
        this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(sourceNation, 2, targetNation);
        return 1;
      }
      this->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetNation, 2, sourceNation);
      return 1;
    }
    if (static_cast<char>(mode) == 0) {
      g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, targetNation, 1);
    } else {
      g_pDiplomacyTurnStateManager->ApplyRelationCode4Slot7c(this->nationSlot, sourceNation, 0);
    }
  }
  return 1;
}

// Port-zone refit fields live on TZone (+0x28..+0x30).

// FUNCTION: IMPERIALISM 0x004e8040
char TAutoGreatPower::ReturnZeroSlot9D(int targetNation) {
  if (g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(targetNation, this->nationSlot) != 0) {
    return 0;
  }
  float allyNavyAccum = 0.0f;
  float allyArmyAccum = 0.0f;
  float armyScore = this->GetScoreFactorSlot23C();
  float navyScore = this->GetScoreFactorSlot240();
  int allyIndex = 0;
  if (g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(this->nationSlot) > 0) {
    do {
      int allyNation =
          g_pDiplomacyTurnStateManager->GetNthAlliedMajorNationSlot90(allyIndex, this->nationSlot);
      allyArmyAccum = g_apNationStates[allyNation]->GetScoreFactorSlot23C() + allyArmyAccum;
      allyNavyAccum = g_apNationStates[allyNation]->GetScoreFactorSlot240() + allyNavyAccum;
      ++allyIndex;
    } while (allyIndex <
             g_pDiplomacyTurnStateManager->CountMajorAllianceRelationsSlot8c(this->nationSlot));
  }
  int ownNavyInt = static_cast<int>(navyScore);
  int ownStrength = static_cast<int>(armyScore);
  if (ownStrength <= ownNavyInt) {
    ownStrength = ownNavyInt;
  }
  float ownStrengthScore = static_cast<float>(ownStrength);
  int allyNavyInt = static_cast<int>(allyNavyAccum);
  int allyStrength = static_cast<int>(allyArmyAccum);
  if (allyStrength <= allyNavyInt) {
    allyStrength = allyNavyInt;
  }
  float allyQuarterScore = static_cast<float>(allyStrength / 4);
  float strongestPeer = 0.0f;
  int peerSlot = 0;
  TGreatPower** peerCursor = g_apNationStates;
  do {
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(peerSlot) != 0) {
      float peerArmy = (*peerCursor)->GetScoreFactorSlot23C();
      if (strongestPeer < peerArmy) {
        strongestPeer = peerArmy;
      }
      float peerNavy = (*peerCursor)->GetScoreFactorSlot240();
      if (strongestPeer < peerNavy) {
        strongestPeer = peerNavy;
      }
    }
    ++peerCursor;
    ++peerSlot;
  } while (peerCursor < g_apNationStates + 7);
  int tickQuarter = static_cast<short>(g_pSimMgr->quarterGateTick2c / 4);
  if (tickQuarter >= 0x3c) {
    tickQuarter = 0x3c;
  }
  short relationScore = g_pDiplomacyTurnStateManager
                            ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 +
                                                             static_cast<short>(targetNation)];
  float combinedStrength = ownStrengthScore + allyQuarterScore;
  float combinedScore =
      static_cast<float>((strongestPeer / combinedStrength +
                          (static_cast<float>(relationScore) + ownStrengthScore) /
                              ((static_cast<float>(tickQuarter) + combinedStrength) -
                               g_Compute_Advisory_Map_Value_00653FD4)) *
                         g_Evaluate_Advisory_Case11_Value_00653FD8);
  if (this->ComputeMinisterSkillFloatSlot8A() <= combinedScore) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e9a50
void TAutoGreatPower::SelectAndQueueAdvisoryMapMissionsCase16(void) {
  // Declaration order fixes the frame slot layout (0x12..0x34); the split
  // assignment blocks mirror the original's two init waves around the city gate.
  char hasActiveMission;
  char queueSecondaryDefend;
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
  hasActiveMission = 0;
  bestDirectScore = 0.0f;
  directRegion = -1;
  queueSecondaryDefend = 0;
  if (this->city == 0) {
    return;
  }
  bestScore = 0.0f;
  bestRegion = -1;
  secondBestDirectScore = 0.0f;
  secondBestDirectRegion = -1;

  PopulateCase16AdvisoryMapNodeCandidateState();

  int region;
  for (region = 0; region < 0x180; ++region) {
    unsigned char nodeFlag = mapNodeStateFlags[region];
    int linkRegion = -1;
    if (nodeFlag != 1) {
      continue;
    }
    float score;
    // Garbage on the no-link path exactly like the original: a zero score can never
    // beat bestScore, so the tier value is never consumed there.
    int tier;
    int nodeBuffer[12];
    if (g_pGlobalMapState->HasDirectOrFallbackLinkedNodeType(region, nationSlot, 1) != 0) {
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 0, -1);
      bestDirectScore = score;
      tier = 0;
      directRegion = region;
    } else if (g_pGlobalMapState->CollectSecondDegreeLinksWithMinorNationFallback(
                   region, nationSlot, nodeBuffer, 1) != 0) {
      linkRegion = nodeBuffer[0];
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 1, linkRegion);
      tier = 1;
    } else if (g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(region) != 0) {
      score = ComputeAdvisoryMapNodeCompositeScoreByMode(region, 2, -1);
      tier = 2;
    } else {
      score = g_Compute_Advisory_Zero_00653FD0;
      mapNodeStateFlags[region] = 0;
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
    if (portZoneStateFlags[zone->GetContextOrdinalOrInvalid()] == 1) {
      float zoneScore = ComputeMapActionContextCompositeScoreForNation(zone);
      if (zoneScore > bestScore) {
        bestPortZone = zone;
        zone->GetContextOrdinalOrInvalid(); // dead call kept from the original
        bestScore = zoneScore;
        bestTier = zone->QueryPortZoneCapability() ? 4 : 2;
      }
    }
  }

  int tier = bestTier;
  if (tier != -1) {
    char acceptMission = 0;
    if (g_afAdvisoryMissionTierThresholdByMinisterSkill_00653F18[defenseMinister->skillIndexC]
                                                                [tier] < bestScore) {
      acceptMission = 1;
    } else if (g_pDiplomacyTurnStateManager->HasAnyWarRelationForNation(nationSlot) != 0) {
      CIterator missionIter(missionQueue);
      for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
           mission = static_cast<TMission*>(missionIter.Advance())) {
        if ((mission->marker11 & 1) != 0) {
          hasActiveMission = 1;
          break;
        }
      }
      if (hasActiveMission == 0) {
        queueSecondaryDefend = 1;
      }
    }
    if (acceptMission != 0) {
      if (bestPortZone == 0) {
        if (tier == 2) {
          TZone* contextZone =
              g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(bestRegion);
          if (contextZone != 0) {
            QueueMapActionMissionFromCandidateAndMarkState(static_cast<eMissionType>(tier), -1,
                                                           contextZone, bestRegion);
          } else {
            mapNodeStateFlags[bestRegion] = 0;
          }
        } else if (bestLinkRegion != -1) {
          QueueMapActionMissionFromCandidateAndMarkState(static_cast<eMissionType>(tier),
                                                         bestLinkRegion, 0, bestRegion);
        } else {
          QueueMapActionMissionFromCandidateAndMarkState(static_cast<eMissionType>(tier),
                                                         bestRegion, 0, -1);
        }
      } else {
        QueueMapActionMissionFromCandidateAndMarkState(static_cast<eMissionType>(tier), -1,
                                                       bestPortZone, -1);
      }
    }
    if (queueSecondaryDefend != 0 && secondBestDirectRegion != -1) {
      QueueMapActionMissionFromCandidateAndMarkState(kMissionTypeAttackProvince,
                                                     secondBestDirectRegion, 0, -1);
    }
  }

  // War fallback: when any eligible major is at war with us, queue defend missions on
  // non-queued contexts whose secondary neighbors include this nation.
  char anyEligibleAtWar = 0;
  int n;
  for (n = 0; n < 7 && anyEligibleAtWar == 0; ++n) {
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(static_cast<short>(n), nationSlot) != 0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(n)) != 0) {
      anyEligibleAtWar = 1;
    }
  }
  if (anyEligibleAtWar != 0) {
    for (zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      short contextOrdinal = zone->GetContextOrdinalOrInvalid();
      if (portZoneStateFlags[contextOrdinal] != 2 &&
          zone->HasSecondaryNeighborWithNationTag(nationSlot) != 0) {
        for (n = 0; n < 7; ++n) {
          if (n != nationSlot &&
              g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationSlot, static_cast<short>(n)) !=
                  0 &&
              (zone->field10 & static_cast<unsigned char>(1 << n)) != 0) {
            portZoneStateFlags[contextOrdinal] = 1;
            QueueMapActionMissionFromCandidateAndMarkState(kMissionTypeDefendProvince, -1, zone,
                                                           -1);
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004e9ed0
void TAutoGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                           int policyCode,
                                                                           int sourceNationSlot) {
  this->SetCandidateNationFlagAndPortZoneState(targetNationSlot);
  TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetNationSlot, policyCode,
                                                                    sourceNationSlot);
}

// FUNCTION: IMPERIALISM 0x004e9f10
char TAutoGreatPower::HasActiveCandidateNationSlots(void) {
  char anyActive = 0;
  int candidate = 0;
  TGreatPower** nationCursor = g_apNationStates;
  do {
    if (*nationCursor == 0) {
      this->candidateNationFlags[candidate] = 0;
    } else if (this->candidateNationFlags[candidate] != 0) {
      anyActive = 1;
    }
    ++nationCursor;
    ++candidate;
  } while (nationCursor < g_apNationStates + 7);
  candidate = 7;
  TMinor** minorCursor = g_apNationAuxRuntimeStateSlots;
  do {
    if (this->candidateNationFlags[candidate] != 0) {
      if ((*minorCursor)->ownedRegionList->GetSize() == 0) {
        this->candidateNationFlags[candidate] = 0;
        if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(this->nationSlot, candidate) !=
            0) {
          g_pDiplomacyTurnStateManager->SetRelationCodeSlot78Final(this->nationSlot, candidate, 4);
        }
      } else {
        anyActive = 1;
      }
    }
    ++minorCursor;
    ++candidate;
  } while (minorCursor < g_apNationAuxRuntimeStateSlots + 16);
  return anyActive;
}

// FUNCTION: IMPERIALISM 0x004e9ff0
void TAutoGreatPower::SetCandidateNationFlagAndPortZoneState(int targetNation) {
  if (this->HasActiveCandidateNationSlots() != 0) {
    int nation = 0;
    TCountry** descriptorCursor = g_apTerrainTypeDescriptorTable;
    do {
      if (*descriptorCursor != 0 && nation != static_cast<short>(this->nationSlot)) {
        if (g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
                nation, static_cast<short>(this->nationSlot)) == 0) {
          this->NotifyAllianceSlot214(nation);
        }
      }
      ++descriptorCursor;
      ++nation;
    } while (descriptorCursor < g_apTerrainTypeDescriptorTable + 0x17);
  }
  this->candidateNationFlags[targetNation] = 1;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetSize() > 0) {
      short ownerTag;
      if (g_apTerrainTypeDescriptorTable[targetNation] == 0 ||
          (ownerTag = g_apTerrainTypeDescriptorTable[targetNation]->encodedNationSlot,
           ownerTag < 100) ||
          199 < ownerTag) {
        g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(
            static_cast<short>(targetNation));
        short portZoneId = g_pMapActionContextListHead->GetContextOrdinalOrInvalid();
        this->portZoneStateFlags[portZoneId] = 1;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ea0e0
void TAutoGreatPower::NotifyAllianceSlot214(int targetNation) {
  this->candidateNationFlags[targetNation] = 0;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetSize() > 0) {
      g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
      short portZoneId = g_pMapActionContextListHead->GetContextOrdinalOrInvalid();
      this->portZoneStateFlags[portZoneId] = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004ea150
void TAutoGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) {
  TGreatPower::SetNationTransferTargetCodeAndNotifyEligiblePeers(targetNationSlot);

  int i = 0;
  for (i = 0; i < 6; ++i) {
    this->actionMetricByQuarter[i] = 0;
  }
  for (i = 0; i < kMapNodeCount; ++i) {
    this->mapNodeStateFlags[i] = 0;
  }
  for (i = 0; i < kPortZoneCount; ++i) {
    this->portZoneStateFlags[i] = 0;
  }
}

// FUNCTION: IMPERIALISM 0x004ea1c0
void TAutoGreatPower::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  CIterator missionCursor(this->missionQueue);
  TMission* mission = static_cast<TMission*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    if (mission->MatchesMissionKeySlot4C(3, regionId, 0) != 0) {
      CPtrList* listState = &this->missionQueue->listState;
      POSITION pos = listState->Find(mission, 0);
      if (pos != 0) {
        listState->RemoveAt(pos);
      }
      mission->Free();
      break;
    }
    mission = static_cast<TMission*>(missionCursor.Advance());
  }
  this->mapNodeStateFlags[regionId] = 0;
  TGreatPower::RemoveRegionIdFromNationOwnedRegionList(regionId);
}

// FUNCTION: IMPERIALISM 0x004ea290
void TAutoGreatPower::AddRegionIdToNationOwnedRegionList(int regionId) {
  TGreatPower::AddRegionIdToNationOwnedRegionList(regionId);

  if (regionId >= 0 && regionId < kMapNodeCount) {
    this->mapNodeStateFlags[regionId] = 1;
    this->QueueMapActionMissionFromCandidateAndMarkState(kMissionTypeDefendProvince, regionId, 0,
                                                         -1);
  }
}

// FUNCTION: IMPERIALISM 0x004ea300
void TAutoGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) {
  TGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(targetNation);
  int ordinal = 1;
  TLongintList* regionList = g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList;
  if (regionList->GetSize() > 0) {
    do {
      int regionId = regionList->At(ordinal);
      this->mapNodeStateFlags[regionId] = 1;
      this->QueueMapActionMissionFromCandidateAndMarkState(kMissionTypeDefendProvince, regionId, 0,
                                                           -1);
      ++ordinal;
    } while (ordinal <= regionList->GetSize());
  }
  TZone* portZone =
      g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
  if (portZone->PrimaryZoneHeapCapacity() == 0) {
    void* grownArray = realloc(portZone->PrimaryZoneHeapData(), 8);
    if (grownArray == 0) {
      portZone->PrimaryZoneHeapData() =
          static_cast<TZone**>(realloc(portZone->PrimaryZoneHeapData(), 4));
      portZone->PrimaryZoneHeapCapacity() = 1;
    } else {
      portZone->PrimaryZoneHeapData() = static_cast<TZone**>(grownArray);
      portZone->PrimaryZoneHeapCapacity() = 2;
    }
  }
  if (portZone->PrimaryZoneHeapSize() == 0) {
    portZone->PrimaryZoneHeapSize() = 1;
  }
  TZone* firstOrder = portZone->PrimaryZoneHeapData()[0];
  short portZoneId = g_pMapActionContextListHead->GetContextOrdinalOrInvalid();
  this->portZoneStateFlags[portZoneId] = 1;
  this->QueueMapActionMissionFromCandidateAndMarkState(kMissionTypeDefendProvince, -1, firstOrder,
                                                       -1);
}

// FUNCTION: IMPERIALISM 0x004ea430
void TAutoGreatPower::DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) {
  (void)orderKind;
  (void)payload;
  (void)flags;
}

// FUNCTION: IMPERIALISM 0x004ea450
void TAutoGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {}

// FUNCTION: IMPERIALISM 0x004ea470
void TAutoGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets();
  short carryValue = this->needCurrentByType[0x13];
  this->needCurrentByType[0x13] = 0;
  this->needCurrentByType[0x14] = static_cast<short>(this->needCurrentByType[0x14] + carryValue);
}

// FUNCTION: IMPERIALISM 0x004ea990
undefined TAutoGreatPower::IterateLinkedListCursorAndRelinkNodeOwners_004ea990() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004eaa20
void TAutoGreatPower::NoOpTailStateHookSlot2B4(void) {}

// FUNCTION: IMPERIALISM 0x004eae70
void TAutoGreatPower::NoOpTailStateHookSlot2B8(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x004eb0d0
void TAutoGreatPower::PruneInvalidTrackedEntriesAndNotifyOwner(void) {
  for (;;) {
    CIterator missionCursor(this->missionQueue);
    TMission* mission = static_cast<TMission*>(missionCursor.Reset());
    TMission* replacement;
    for (;;) {
      if (missionCursor.More() == 0) {
        return;
      }
      replacement = mission->GetReplacementSlot48();
      if (replacement != mission) {
        break;
      }
      mission = static_cast<TMission*>(missionCursor.Advance());
    }
    CPtrList* listState = &this->missionQueue->listState;
    POSITION pos = listState->Find(mission, 0);
    if (pos != 0) {
      listState->RemoveAt(pos);
    }
    mission->Free();
    if (replacement != 0) {
      this->missionQueue->AddTail(replacement);
    }
  }
}
TAutoGreatPower::~TAutoGreatPower() {}
