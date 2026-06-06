#include "decomp_types.h"
#include "game/TAutoGreatPower.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

undefined4 thunk_ConstructNationStateBase_Vtbl653938(void);
undefined4 thunk_GetResourceDescriptorWeightWord0ByType(void);

static const unsigned int kAddrClassDescTAutoGreatPower = 0x00653F90;
static const unsigned int kAddrVtblTAutoGreatPower = 0x00654088;
static const int kNationSlotCount = 0x17;
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

// FUNCTION: IMPERIALISM 0x004e6b50
void* TAutoGreatPower::ConstructTAutoGreatPowerBaseState(void) {
  void(__fastcall * constructBase)(void*, int) =
      reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_ConstructNationStateBase_Vtbl653938);
  constructBase(this, 0);
  this->autoTrackedListB60 = 0;
  *reinterpret_cast<void**>(this) = reinterpret_cast<void*>(kAddrVtblTAutoGreatPower);
  return this;
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

  this->diplomacyCounterA4 = static_cast<short>(total);
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
