#include "game/TForeignMinister.h"

#include "game/TDealList.h"
#include "game/TGreatPower.h"
#include "game/TGreatPower_internal.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TDiplomacyMgr.h"
#include "game/diplomacy_globals.h"
#include "game/mfc.h"
#include "game/TStream.h"

#include "game/nation_slot_eligibility.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
CRuntimeClass g_pClassDescTForeignMinister = {nullptr, 0, 0, nullptr, nullptr};
}

extern undefined4 GenerateThreadLocalRandom15(void);

static __inline unsigned int GenerateThreadLocalRandom15Value(void) {
  return reinterpret_cast<unsigned int(__cdecl*)(void)>(GenerateThreadLocalRandom15)();
}

static const short kPrimaryNationUnset = static_cast<short>(0xfff6);

// FUNCTION: IMPERIALISM 0x0052f050
CRuntimeClass* TForeignMinister::GetRuntimeClass() const {
  return &g_pClassDescTForeignMinister;
}

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
void TForeignMinister::InitializeStateAndCounters() {
  this->InitializeBaseOrderArray(0);
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
void TForeignMinister::MinisterSlot0A() {}

// FUNCTION: IMPERIALISM 0x0052f4b0
void TForeignMinister::MinisterSlot12() {}

// FUNCTION: IMPERIALISM 0x0052f4f0
void TForeignMinister::Call4C() {}

// FUNCTION: IMPERIALISM 0x0052f520
void TForeignMinister::MinisterSlot14() {}

// FUNCTION: IMPERIALISM 0x0052f540
void TForeignMinister::Call54() {}

// FUNCTION: IMPERIALISM 0x0052f570
void TForeignMinister::MinisterSlot21() {}

// FUNCTION: IMPERIALISM 0x0052f730
char TForeignMinister::MinisterSlot22() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0052f7b0
void TForeignMinister::Call8C() {
  char* raw = reinterpret_cast<char*>(this);
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);

  if (*reinterpret_cast<short*>(raw + 0x10) != kPrimaryNationUnset) {
    TSortedByRelationshipList* relationshipList =
        TSortedByRelationshipList::CreateTSortedByRelationshipListInstance();
    if (relationshipList != 0) {
      relationshipList->relationType = 4;
    }
    if (relationshipList != 0) {
      g_pDiplomacyTurnStateManager->BuildRelationshipListSlot88(owner->nationSlot, 1,
                                                                relationshipList);
      short* nationSlotPtr =
          static_cast<short*>(relationshipList->GetEntrySlot2C(relationshipList->GetSize()));
      g_apNationStates[*nationSlotPtr]->AssignNeedSlotFromSourceSlot19C(
          *reinterpret_cast<short*>(raw + 0x10), owner->nationSlot);
      relationshipList->ReleaseSlot24();
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
      fallbackNationSlot = GenerateThreadLocalRandom15Value() % 7;
      if (IsNationSlotEligibleForEventProcessing(static_cast<short>(fallbackNationSlot)) != 0) {
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
  this->MinisterSlot12();
  char* raw = reinterpret_cast<char*>(this);
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);
  int skipMissionSlot1A = 0;
  if (*reinterpret_cast<short*>(raw + 0x18) < *reinterpret_cast<short*>(raw + 0x1a)) {
    if (this->MinisterSlot22() == 0) {
      skipMissionSlot1A = 1;
    }
  }
  if (skipMissionSlot1A == 0) {
    owner->foreignMinister->MinisterSlot1A(*reinterpret_cast<short*>(raw + 0x1c));
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
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);
  short nationSlot = owner->nationSlot;
  static const short kOrderKinds[] = {0, 1, 2, 3, 4, 5, 6};
  int loopCount = IsRecruitTier2EnabledForNation(nationSlot) + 5;
  if (loopCount != 0) {
    const short* orderKindCursor = kOrderKinds;
    do {
      int roll = GenerateThreadLocalRandom15Value();
      short orderKind = *orderKindCursor;
      short weightThreshold =
          g_pNationInteractionStateManager->QueryProposalWeightSlot4C(orderKind);
      if (roll % 100 + 200 < static_cast<int>(weightThreshold)) {
        short metric = owner->GetDiplomacyExternalStateB6ByTarget(orderKind);
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

  int roll = GenerateThreadLocalRandom15Value();
  short tradeWeight = g_pNationInteractionStateManager->QueryProposalWeightSlot4C(5);
  if (roll % 100 + 200 < static_cast<int>(tradeWeight)) {
    short tradeMetric = owner->GetDiplomacyExternalStateB6ByTarget(5);
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
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);
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
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);
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
void TForeignMinister::Call58() {}

// FUNCTION: IMPERIALISM 0x0052fd80
void TForeignMinister::MinisterSlot18() {}

// FUNCTION: IMPERIALISM 0x0052fda0
void TForeignMinister::MinisterSlot19() {}

// FUNCTION: IMPERIALISM 0x0052fdc0
void TForeignMinister::MinisterSlot1A(short arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x0052fe90
void TForeignMinister::MinisterSlot17() {}

// FUNCTION: IMPERIALISM 0x00530200
void TForeignMinister::MinisterSlot1E() {}

// FUNCTION: IMPERIALISM 0x005308b0
void TForeignMinister::MinisterSlot1C() {}

// FUNCTION: IMPERIALISM 0x00530b30
void TForeignMinister::MinisterSlot1D() {}

// FUNCTION: IMPERIALISM 0x00530bb0
void TForeignMinister::MinisterSlot1B() {}

// FUNCTION: IMPERIALISM 0x00530fa0
void TForeignMinister::MinisterSlot1F() {}

// FUNCTION: IMPERIALISM 0x00531110
void TForeignMinister::Call80() {}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
