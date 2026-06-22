#include "decomp_types.h"
#include "game/TAutoGreatPower.h"
#include "game/CIterator.h"
#include "game/TDiplomacyMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TPtrList.h"
#include "game/nation_slot_eligibility.h"
#include "game/TSimMgr.h"
#include "game/TMinister.h"
#include "game/TForeignMinister.h"
#include "game/TCityInteriorMinister.h"
#include "game/TDefenseMinister.h"
#include "game/TMessageObject.h"
#include "game/TStream.h"
#include "game/TMinor.h"
#include "game/TPtrList.h"
#include "game/TCity.h"
#include "game/TTrackedObject.h"
#include "game/diplomacy_globals.h"
#include "game/TZone.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

#include "game/TShip.h"
undefined4 thunk_DispatchTaggedGameStateEvent1F20(void); // 0x00406efb -> 0x0054a340
undefined4 GenerateThreadLocalRandom15(void);
undefined4 thunk_GetShortAtOffset14OrInvalid(void);

static __inline short GetShortAtOffset14OrInvalidValue(void) {
  return reinterpret_cast<short(__cdecl*)(void)>(thunk_GetShortAtOffset14OrInvalid)();
}

extern "C" {
extern double g_DAT_00653fc0_Value_00653FC0; // 1/255
extern double g_DAT_00653fc8_Value_00653FC8; // 32767.0
}

static const unsigned int kAddrClassDescTAutoGreatPower = 0x00653F90;
// kNationSlotCount (0x17) comes from TDiplomacyMgr.h.
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;
static const unsigned int kAddrAdvanceTurnMachineState = 0x00695278;
static const int kMapNodeCount = 0x180;
static const int kPortZoneCount = 0x70;

undefined4 PopulateCase16AdvisoryMapNodeCandidateState(void);

static __inline void SwapShortArrayBytes(void* base, int count) {
  unsigned char* bytes = reinterpret_cast<unsigned char*>(base);
  int i = 0;
  while (i < count) {
    unsigned char t = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = t;
    bytes += 2;
    ++i;
  }
}

#include "game/TQueueObject.h"

class TMinisterProposalReplayView {
public:
  virtual void dummy00() = 0;
  virtual void dummy01() = 0;
  virtual void dummy02() = 0;
  virtual void dummy03() = 0;
  virtual void dummy04() = 0;
  virtual void dummy05() = 0;
  virtual void dummy06() = 0;
  virtual void dummy07() = 0;
  virtual void dummy08() = 0;
  virtual void dummy09() = 0;
  virtual void dummy0a() = 0;
  virtual void dummy0b() = 0;
  virtual void dummy0c() = 0;
  virtual void dummy0d() = 0;
  virtual void dummy0e() = 0;
  virtual void dummy0f() = 0;
  virtual void dummy10() = 0;
  virtual void dummy11() = 0;
  virtual void dummy12() = 0;
  virtual void dummy13() = 0;
  virtual void dummy14() = 0;
  virtual void dummy15() = 0;
  virtual void dummy16() = 0;
  virtual void dummy17() = 0;
  virtual void dummy18() = 0;
  virtual void dummy19() = 0;
  virtual void dummy1a() = 0;
  virtual void dummy1b() = 0;
  virtual void dummy1c() = 0;
  virtual void dummy1d() = 0;
  virtual void dummy1e() = 0;
  virtual void QueueProposalRowSlot7C(int queueIndex) = 0;

protected:
  ~TMinisterProposalReplayView() {}
};

static __inline int ProposalQueue_ReadCount(void* queue) {
  return static_cast<TQueueObject*>(queue)->GetEntryCount();
}


// FUNCTION: IMPERIALISM 0x004e6b10
void TAutoGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) {}

extern "C" {
extern float g_Compute_Advisory_Map_Value_00653FD4;      // -100.0f
extern double g_Evaluate_Advisory_Case11_Value_00653FD8; // 0.5
}

undefined4 ReallocateHeapBlockWithAllocatorTracking(void);


// FUNCTION: IMPERIALISM 0x004e6b30
CRuntimeClass* TAutoGreatPower::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTAutoGreatPower);
}

TAutoGreatPower::TAutoGreatPower() : TGreatPower() {
  missionQueue = 0;
}


// FUNCTION: IMPERIALISM 0x004e6b50
void* TAutoGreatPower::ConstructTAutoGreatPowerBaseState(void) {
  new (this) TAutoGreatPower();
  return this;
}


// SYNTHETIC: IMPERIALISM 0x004e6b80
// TAutoGreatPower::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x004e6bb0
// TAutoGreatPower::~TAutoGreatPower


// FUNCTION: IMPERIALISM 0x004e7230
void TAutoGreatPower::Free(void) {
  if (this->missionQueue != 0) {
    int ordinal = this->missionQueue->GetCountSlot48();
    for (; ordinal > 0; --ordinal) {
      TTrackedObject* entry =
          static_cast<TTrackedObject*>(this->missionQueue->GetEntryByOrdinalSlot4C(ordinal));
      entry->NotifyDetachSlot0C();
      this->missionQueue->RemoveAtOrdinalSlot50(ordinal);
      entry->Free();
    }
    if (this->missionQueue != 0) {
      this->missionQueue->FreePayloadsAndDestroySlot58();
    }
    this->missionQueue = 0;
  }
  TGreatPower::Free();
}


// FUNCTION: IMPERIALISM 0x004e7510
void TAutoGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
  if (g_pLocalizationTable->redrawEnabled != 0) {
    // TEMP: 0x0054a340 is a thiscall on g_pGameFlowState (0x6a43c8); model it as a
    // real method once the game-flow event sink class is recovered.
    reinterpret_cast<void(__stdcall*)(int, int, int)>(thunk_DispatchTaggedGameStateEvent1F20)(
        0x6c6f7374, this->nationSlot, -3);
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


// FUNCTION: IMPERIALISM 0x004e7680
void TAutoGreatPower::AssignNeedSlotFromSourceSlot19C(int needSlot, int sourceNation) {
  if (g_apNationStates[static_cast<short>(sourceNation)]->diplomacyEligibilityA0 != 0) {
    if (static_cast<short>(needSlot) != 5) {
      short relationScore = g_pDiplomacyTurnStateManager
                                ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 +
                                                                 static_cast<short>(sourceNation)];
      double scaledScore = static_cast<double>(relationScore) * g_DAT_00653fc0_Value_00653FC0;
      int roll = GenerateThreadLocalRandom15();
      if (static_cast<double>(roll) > scaledScore * g_DAT_00653fc8_Value_00653FC8) {
        this->OrphanCallChain_C4_I28_004e75c0(needSlot);
      }
      return;
    }
  } else if (static_cast<short>(needSlot) != 5) {
    short metricCap = 10;
    if (this->GetDiplomacyExternalStateB6ByTarget(static_cast<short>(needSlot)) < 10) {
      metricCap = this->GetDiplomacyExternalStateB6ByTarget(static_cast<short>(needSlot));
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
  if (this->GetDiplomacyExternalStateB6ByTarget(5) != 0 &&
      this->QueryNationMetricBySlot7C(5) != -1) {
    short metric = this->GetDiplomacyExternalStateB6ByTarget(5);
    int assignAmount = (metric != 1) + 1;
    if (this->tradeCapacity < static_cast<short>(assignAmount)) {
      assignAmount = this->tradeCapacity;
    }
    this->SetDiplomacyState1c6ClampedToCounterA4(5, static_cast<short>(assignAmount));
  }
}


// FUNCTION: IMPERIALISM 0x004e72c0
void TAutoGreatPower::ReadFrom(TStream* stream) {
  TGreatPower::ReadFrom(stream);
  stream->ReadBytes(this->actionMetricByQuarter, 0x0C);
  SwapShortArrayBytes(this->actionMetricByQuarter, 6);

  stream->ReadBytes(this->mapNodeStateFlags, 0x180);
  stream->ReadBytes(this->portZoneStateFlags, 0x70);

  TPtrList* missionQueue = this->missionQueue;
  if (missionQueue->GetCountSlot48() != 0) {
    missionQueue->FreePayloadsSlot54();
  }
  missionQueue->ReadFrom(stream);

  int missionContext = 0;
  stream->ReadBytes(&missionContext, 4);
  for (int queueIndex = 1; queueIndex < 0x71; ++queueIndex) {
    missionContext = 0;
    char hasMission = stream->ReadByte(&missionContext);
    if (hasMission != 0) {
      missionQueue->AddTailSlot30(reinterpret_cast<void*>(missionContext));
    }
  }

  if (*reinterpret_cast<int*>(kAddrAdvanceTurnMachineState) < 0x39) {
    this->QueueMapActionMissionFromCandidateAndMarkState(5, -1, 0, -1);
  }
}


// FUNCTION: IMPERIALISM 0x004e73f0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TAutoGreatPower::WriteTo(TStream* stream) {
  TGreatPower::WriteTo(stream);

  TMessageObject* message = reinterpret_cast<TMessageObject*>(stream);
  short* quarterMetric = this->actionMetricByQuarter;
  int remaining = 6;
  do {
    short value = *quarterMetric;
    unsigned char* bytes = reinterpret_cast<unsigned char*>(&value);
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    message->AppendBytesSlot78(&value, 2);
    ++quarterMetric;
    --remaining;
  } while (remaining != 0);

  message->AppendBytesSlot78(this->mapNodeStateFlags, 0x180);
  message->AppendBytesSlot78(this->portZoneStateFlags, 0x70);

  TPtrList* missionQueue = this->missionQueue;
  missionQueue->WriteTo(stream);
  int missionQueueCount = missionQueue->GetCountSlot48();

  int zeroWord = 0;
  message->AppendBytesSlot78(&zeroWord, 4);
  int index = 1;
  if (index <= missionQueueCount) {
    do {
      int value = reinterpret_cast<int>(missionQueue->GetEntryByOrdinalSlot4C(index));
      message->WriteEntrySlotB4(value, 0);
      ++index;
    } while (index <= missionQueueCount);
  }
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif


// FUNCTION: IMPERIALISM 0x004e7630
void TAutoGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                                     int multiplier) {
  if (delta < 0 && resourceIndex > 6 && resourceIndex < 0x0D) {
    this->needCurrentByType[resourceIndex] =
        static_cast<short>(this->needCurrentByType[resourceIndex] + delta);
  }

  TGreatPower::ApplyIndexedResourceDeltaAndAdjustNationTotals(resourceIndex, delta, multiplier);
}


// FUNCTION: IMPERIALISM 0x004e7810
void TAutoGreatPower::ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) {
  int total = 0;
  for (int resourceType = 0; static_cast<short>(resourceType) < 0x0E; ++resourceType) {
    short resourceWeight = GetResourceDescriptorWeightWord0ByType(static_cast<short>(resourceType));
    short relationWeight = *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(this->city) +
                                                     0x5C + resourceType * 2);
    total += static_cast<short>(resourceWeight * relationWeight);
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


// FUNCTION: IMPERIALISM 0x004e7990
void TAutoGreatPower::ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) {
  this->foreignMinister->Call90();
  this->foreignMinister->Call94();
}


// FUNCTION: IMPERIALISM 0x004e7910
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel2() {
}


// FUNCTION: IMPERIALISM 0x004e7930
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel1() {
}


// FUNCTION: IMPERIALISM 0x004e7950
void TAutoGreatPower::DispatchGreatPowerQuarterlyStatusMessageLevel0() {
}


// FUNCTION: IMPERIALISM 0x004e7970
undefined TAutoGreatPower::DispatchNationStateEventCode10() {
  return 0;
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
        short current = this->GetDiplomacyExternalStateB6ByTarget(needSlot);
        short remaining;
        if (current < pending) {
          remaining = 0;
        } else {
          remaining = static_cast<short>(current - pending);
        }
        this->SetCityFieldB6AndRefresh(needSlot, remaining);
      }
      *pendingMetric = 0;
      ++pendingMetric;
    }
    TGreatPower::ClearDiplomacyState1c6Block();
  }
}


// FUNCTION: IMPERIALISM 0x004e7b20
bool TAutoGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) {
  return TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks(arg1, arg2);
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
      char hasAllianceGuard = g_pDiplomacyTurnStateManager->HasAllianceGuardSlot60(
          targetNationId, this->nationSlot);
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


// FUNCTION: IMPERIALISM 0x004e7c50
void TAutoGreatPower::NotifyActionSlot94(int sourceNation, int actionCode) {
  if (actionCode == 0x131) {
    this->SetCandidateNationFlagAndPortZoneState(static_cast<short>(sourceNation));
  }
  TGreatPower::NotifyActionSlot94(sourceNation, actionCode);
}


// FUNCTION: IMPERIALISM 0x004e7af0
void TAutoGreatPower::BeginTurnDiplomacyPrePassSlot1c8() {
  if (this->city != 0) {
    this->foreignMinister->Call58();
  }
}


// FUNCTION: IMPERIALISM 0x004e7be0
void TAutoGreatPower::ProcessPendingDiplomacyProposalQueue(void) {
  if (this->city == 0) {
    return;
  }

  int rowIndex = 1;
  if (ProposalQueue_ReadCount(this->proposalQueue) >= rowIndex) {
    do {
      reinterpret_cast<TMinisterProposalReplayView*>(this->foreignMinister)
          ->QueueProposalRowSlot7C(rowIndex);
      ++rowIndex;
    } while (rowIndex <= ProposalQueue_ReadCount(this->proposalQueue));
  }

  this->ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants();
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif


// FUNCTION: IMPERIALISM 0x004e7ca0
void TAutoGreatPower::DispatchTurnEvent2103WithNationFromRecord() {
}


// FUNCTION: IMPERIALISM 0x004e7cc0
int TAutoGreatPower::CheckTransitionSlot27C(int targetNation, int sourceNation) {
  char allBeatable = 1;
  char beatableByNation[7] = {0, 0, 0, 0, 0, 0, 0};
  int nation = 0;
  do {
    if (nation > 6) {
      break;
    }
    if (IsNationSlotEligibleForEventProcessing(nation) != 0 &&
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
    if (IsNationSlotEligibleForEventProcessing(peerSlot) != 0) {
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
  int tickQuarter = static_cast<short>(g_pLocalizationTable->quarterGateTick2c / 4);
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
      if ((*minorCursor)->ownedRegionList->GetCountSlot48() == 0) {
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
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetCountSlot48() >
        0) {
      short ownerTag;
      if (g_apTerrainTypeDescriptorTable[targetNation] == 0 ||
          (ownerTag = g_apTerrainTypeDescriptorTable[targetNation]->encodedNationSlot,
           ownerTag < 100) ||
          199 < ownerTag) {
        TZone::FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
        short portZoneId = GetShortAtOffset14OrInvalidValue();
        this->portZoneStateFlags[portZoneId] = 1;
      }
    }
  }
}


// FUNCTION: IMPERIALISM 0x004ea0e0
void TAutoGreatPower::NotifyAllianceSlot214(int targetNation) {
  this->candidateNationFlags[targetNation] = 0;
  if (g_apTerrainTypeDescriptorTable[targetNation] != 0) {
    if (g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList->GetCountSlot48() >
        0) {
      TZone::FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
      short portZoneId = GetShortAtOffset14OrInvalidValue();
      this->portZoneStateFlags[portZoneId] = 0;
    }
  }
}


// FUNCTION: IMPERIALISM 0x004ea1c0
void TAutoGreatPower::RemoveRegionIdFromNationOwnedRegionList(int regionId) {
  CIterator missionCursor(this->missionQueue);
  TTrackedObject* mission = static_cast<TTrackedObject*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    if (mission->MatchesMissionKeySlot4C(3, regionId, 0) != 0) {
      CPtrList* listState = &reinterpret_cast<TPtrList*>(this->missionQueue)->listState;
      POSITION pos = listState->Find(mission, 0);
      if (pos != 0) {
        listState->RemoveAt(pos);
      }
      mission->Free();
      break;
    }
    mission = static_cast<TTrackedObject*>(missionCursor.Advance());
  }
  this->mapNodeStateFlags[regionId] = 0;
  TGreatPower::RemoveRegionIdFromNationOwnedRegionList(regionId);
}


// FUNCTION: IMPERIALISM 0x004ea300
void TAutoGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) {
  TGreatPower::ResetNationDiplomacySlotsAndMarkRelatedNations(targetNation);
  int ordinal = 1;
  TPtrList* regionList = g_apTerrainTypeDescriptorTable[targetNation]->ownedRegionList;
  if (regionList->GetCountSlot48() > 0) {
    do {
      int regionId = regionList->GetIntByOrdinalSlot24(ordinal);
      this->mapNodeStateFlags[regionId] = 1;
      this->QueueMapActionMissionFromCandidateAndMarkState(3, regionId, 0, -1);
      ++ordinal;
    } while (ordinal <= regionList->GetCountSlot48());
  }
  TZone* portZone = TZone::FindFirstPortZoneContextByNation(static_cast<short>(targetNation));
  if (portZone->portZoneEntryCount2c == 0) {
    void* grownArray = reinterpret_cast<void*(__cdecl*)(void*, int)>(
        ReallocateHeapBlockWithAllocatorTracking)(portZone->portZoneEntries28, 8);
    if (grownArray == 0) {
      portZone->portZoneEntries28 = static_cast<int*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
          ReallocateHeapBlockWithAllocatorTracking)(portZone->portZoneEntries28, 4));
      portZone->portZoneEntryCount2c = 1;
    } else {
      portZone->portZoneEntries28 = static_cast<int*>(grownArray);
      portZone->portZoneEntryCount2c = 2;
    }
  }
  if (portZone->portZoneActiveEntryCount30 == 0) {
    portZone->portZoneActiveEntryCount30 = 1;
  }
  void* firstOrder = reinterpret_cast<void*>(portZone->portZoneEntries28[0]);
  short portZoneId = GetShortAtOffset14OrInvalidValue();
  this->portZoneStateFlags[portZoneId] = 1;
  this->QueueMapActionMissionFromCandidateAndMarkState(3, -1, reinterpret_cast<int>(firstOrder),
                                                       -1);
}


// FUNCTION: IMPERIALISM 0x004e9a50
void TAutoGreatPower::NoOpSlotA2(void) {
  if (this->city == 0) {
    return;
  }

  // TEMP: 0x004e92b0 (PopulateCase16AdvisoryMapNodeCandidateState) is still an
  // autogen stub; call it through the generic thunk declaration until it is ported.
  PopulateCase16AdvisoryMapNodeCandidateState();

  int bestNodeIndex = -1;
  float bestNodeScore = 0.0f;

  for (int nodeIndex = 0; nodeIndex < 0x180; ++nodeIndex) {
    if (this->mapNodeStateFlags[nodeIndex] != 1) {
      continue;
    }

    float nodeScore = this->ComputeMapActionContextCompositeScoreForNation(nodeIndex);
    if (bestNodeIndex < 0 || nodeScore > bestNodeScore) {
      bestNodeIndex = nodeIndex;
      bestNodeScore = nodeScore;
    }
  }

  if (bestNodeIndex < 0) {
    return;
  }

  this->QueueMapActionMissionFromCandidateAndMarkState(3, bestNodeIndex, 0, -1);

  int strongestNation = -1;
  int strongestNeed = 0;
  for (int nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
    int needValue = static_cast<int>(this->needLevelByNation[nationSlot]);
    if (needValue > strongestNeed) {
      strongestNeed = needValue;
      strongestNation = nationSlot;
    }
  }

  if (strongestNation >= 0 && strongestNation != this->nationSlot) {
    this->QueueInterNationEventType0FForNationPairContext(static_cast<short>(strongestNation),
                                                          this->nationSlot);
  }
}


// FUNCTION: IMPERIALISM 0x004e9ed0
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
void TAutoGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                            int policyCode,
                                                                            int sourceNationSlot) {
  this->SetCandidateNationFlagAndPortZoneState(targetNationSlot);
  TGreatPower::ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(targetNationSlot, policyCode,
                                                                    sourceNationSlot);
}
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif


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


// FUNCTION: IMPERIALISM 0x004ea290
void TAutoGreatPower::AddRegionIdToNationOwnedRegionList(int regionId) {
  TGreatPower::AddRegionIdToNationOwnedRegionList(regionId);

  if (regionId >= 0 && regionId < kMapNodeCount) {
    this->mapNodeStateFlags[regionId] = 1;
    this->QueueMapActionMissionFromCandidateAndMarkState(3, regionId, 0, -1);
  }
}


// FUNCTION: IMPERIALISM 0x004ea470
void TAutoGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets(void) {
  TGreatPower::RebuildNationResourceYieldCountersAndDevelopmentTargets();
  short carryValue = this->needCurrentByType[0x13];
  this->needCurrentByType[0x13] = 0;
  this->needCurrentByType[0x14] = static_cast<short>(this->needCurrentByType[0x14] + carryValue);
}


// FUNCTION: IMPERIALISM 0x004ea430
void TAutoGreatPower::DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) {
  (void)orderKind;
  (void)payload;
  (void)flags;
}


// FUNCTION: IMPERIALISM 0x004ea450
void TAutoGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch(void) {}


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
void TAutoGreatPower::NotifyWarResetSlot290(void) {
  for (;;) {
    CIterator missionCursor(this->missionQueue);
    TTrackedObject* mission = static_cast<TTrackedObject*>(missionCursor.Reset());
    TTrackedObject* replacement;
    for (;;) {
      if (missionCursor.More() == 0) {
        return;
      }
      replacement = mission->GetReplacementSlot48();
      if (replacement != mission) {
        break;
      }
      mission = static_cast<TTrackedObject*>(missionCursor.Advance());
    }
    CPtrList* listState = &reinterpret_cast<TPtrList*>(this->missionQueue)->listState;
    POSITION pos = listState->Find(mission, 0);
    if (pos != 0) {
      listState->RemoveAt(pos);
    }
    mission->Free();
    if (replacement != 0) {
      this->missionQueue->AddTailSlot30(replacement);
    }
  }
}
TAutoGreatPower::~TAutoGreatPower() {}
