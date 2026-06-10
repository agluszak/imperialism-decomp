#include "decomp_types.h"
#include "game/TAutoGreatPower.h"
#include "game/TDiplomacyTurnStateManager.h"
#include "game/TGlobalMapState.h"
#include "game/TListObject.h"
#include "game/TLocalizationRuntime.h"
#include "game/TMinor.h"
#include "game/TTrackedObject.h"
#include "game/diplomacy_globals.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 thunk_GetResourceDescriptorWeightWord0ByType(void);
undefined4 thunk_DispatchTaggedGameStateEvent1F20(void); // 0x00406efb -> 0x0054a340
undefined4 thunk_IsNationSlotEligibleForEventProcessing(void);
undefined4 GenerateThreadLocalRandom15(void);

extern "C" {
extern double g_DAT_00653fc0_Value_00653FC0; // 1/255
extern double g_DAT_00653fc8_Value_00653FC8; // 32767.0
}

static const unsigned int kAddrClassDescTAutoGreatPower = 0x00653F90;
// kNationSlotCount (0x17) comes from TDiplomacyTurnStateManager.h.
static const int kAidAllocationRowCount = 0x10;
static const int kAidAllocationColumnCount = 0x17;

struct TProposalQueueCountView {
  unsigned char pad00[8];
  int count;
};

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
};

static __inline int ProposalQueue_ReadCount(void* queue) {
  return static_cast<TProposalQueueCountView*>(queue)->count;
}

// FUNCTION: IMPERIALISM 0x004e6b30
void* __cdecl TAutoGreatPower::GetTAutoGreatPowerClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTAutoGreatPower);
}

TAutoGreatPower::TAutoGreatPower() : TGreatPower() {
  missionQueue = 0;
}

// FUNCTION: IMPERIALISM 0x004e6b50
void* TAutoGreatPower::ConstructTAutoGreatPowerBaseState(void) {
  new (this) TAutoGreatPower();
  return this;
}

// SYNTHETIC: IMPERIALISM 0x004e6bb0
// TAutoGreatPower::~TAutoGreatPower

// SYNTHETIC: IMPERIALISM 0x004e6b80
// TAutoGreatPower::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004e7230
void TAutoGreatPower::ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void) {
  if (this->missionQueue != 0) {
    int ordinal = this->missionQueue->GetCountSlot48();
    for (; ordinal > 0; --ordinal) {
      TTrackedObject* entry =
          static_cast<TTrackedObject*>(this->missionQueue->GetTrackedEntrySlot4C(ordinal));
      entry->NotifyDetachSlot0C();
      this->missionQueue->RemoveEntryAtSlot50(ordinal);
      entry->Release1C();
    }
    if (this->missionQueue != 0) {
      this->missionQueue->Call58();
    }
    this->missionQueue = 0;
  }
  TGreatPower::ReleaseOwnedGreatPowerObjectsAndDeleteSelf();
}

// FUNCTION: IMPERIALISM 0x004e7510
void TAutoGreatPower::DispatchTurnEvent11F8NoPayloadSlot2AC(void) {
  if (reinterpret_cast<TLocalizationRuntime*>(g_pLocalizationTable)->redrawEnabled != 0) {
    // TEMP: 0x0054a340 is a thiscall on g_pGameFlowState (0x6a43c8); model it as a
    // real method once the game-flow event sink class is recovered.
    reinterpret_cast<void(__stdcall*)(int, int, int)>(thunk_DispatchTaggedGameStateEvent1F20)(
        0x6c6f7374, this->nationSlot, -3);
  }
}

// FUNCTION: IMPERIALISM 0x004e7550
void TAutoGreatPower::VTableIndex54_Provisional(void) {
  if (this->relationManager != 0) {
    this->VTableIndex77_Provisional();
    this->VTableIndex78_Provisional();
  }
}

// FUNCTION: IMPERIALISM 0x004e7680
void TAutoGreatPower::AssignNeedSlotFromSourceSlot19C(int needSlot, int sourceNation) {
  if (g_apNationStates[static_cast<short>(sourceNation)]->diplomacyEligibilityA0 != 0) {
    if (static_cast<short>(needSlot) != 5) {
      short relationScore =
          g_pDiplomacyTurnStateManager
              ->relationStandingScoreMatrix79c[this->nationSlot * 0x17 +
                                               static_cast<short>(sourceNation)];
      double scaledScore = static_cast<double>(relationScore) * g_DAT_00653fc0_Value_00653FC0;
      int roll = GenerateThreadLocalRandom15();
      if (static_cast<double>(roll) > scaledScore * g_DAT_00653fc8_Value_00653FC8) {
        this->EscalateNeedSlot2C8_Provisional(needSlot);
      }
      return;
    }
  } else if (static_cast<short>(needSlot) != 5) {
    short metricCap = 10;
    if (this->QueryNationMetricBySlot78(static_cast<short>(needSlot)) < 10) {
      metricCap = this->QueryNationMetricBySlot78(static_cast<short>(needSlot));
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
  if (this->QueryNationMetricBySlot78(5) != 0 && this->QueryNationMetricBySlot7C(5) != -1) {
    short metric = this->QueryNationMetricBySlot78(5);
    int assignAmount = (metric != 1) + 1;
    if (this->tradeCapacity < static_cast<short>(assignAmount)) {
      assignAmount = this->tradeCapacity;
    }
    this->SetDiplomacyState1c6ClampedToCounterA4(5, static_cast<short>(assignAmount));
  }
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
    if (reinterpret_cast<char(__cdecl*)(int)>(thunk_IsNationSlotEligibleForEventProcessing)(
            nation) != 0 &&
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
    short ownerSlot = minor->ownerNationSlot0e;
    if (ownerSlot < 200) {
      if (ownerSlot < 100) {
        ownerSlot = minor->fallbackNationSlot0c;
      } else {
        ownerSlot = static_cast<short>(ownerSlot - 100);
      }
    } else {
      ownerSlot = static_cast<short>(ownerSlot - 200);
    }
    if (ownerSlot != this->nationSlot) {
      minor->VTableSlot4C_Provisional(this->nationSlot, 1);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x004e7810
void TAutoGreatPower::RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix(void) {
  int total = 0;
  for (int resourceType = 0; static_cast<short>(resourceType) < 0x0E; ++resourceType) {
    short resourceWeight = reinterpret_cast<short(__cdecl*)(int)>(
        thunk_GetResourceDescriptorWeightWord0ByType)(resourceType);
    short relationWeight = *reinterpret_cast<short*>(
        reinterpret_cast<unsigned char*>(this->relationManager) + 0x5C + resourceType * 2);
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

// FUNCTION: IMPERIALISM 0x004e7be0
void TAutoGreatPower::ReplayQueuedDiplomacyProposalRowsAndProcessQueue(void) {
  if (this->relationManager == 0) {
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
