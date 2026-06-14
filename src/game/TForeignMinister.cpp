#include "game/TForeignMinister.h"

#include "game/TGreatPower.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

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

// FUNCTION: IMPERIALISM 0x0052f130
void TForeignMinister::InitializeStateAndCounters() {
  this->InitializeBaseOrderArray(0);
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x10) = static_cast<short>(0xfff6);
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

// FUNCTION: IMPERIALISM 0x00531110
void TForeignMinister::Call80() {}

// FUNCTION: IMPERIALISM 0x0052f7b0
void TForeignMinister::Call8C() {
  char* raw = reinterpret_cast<char*>(this);
  if (*reinterpret_cast<short*>(raw + 0x10) == static_cast<short>(0xfff6)) {
    return;
  }
  // Primary/fallback nation dispatch — full body pending TGreatPower slot wiring.
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
  if (*reinterpret_cast<short*>(raw + 0x10) != static_cast<short>(0xfff6)) {
    short idx = *reinterpret_cast<short*>(raw + 0x10);
    *reinterpret_cast<short*>(raw + 0x1e + idx * 2) = *reinterpret_cast<short*>(raw + 0x12);
    owner->SetDiplomacyState1c6ClampedToCounterA4(idx, static_cast<short>(-1));
  }
}

// FUNCTION: IMPERIALISM 0x0052f9d0
void TForeignMinister::Call94() {
  // RunForeignMinisterVtableSlot94Shared — nation-weight loop; stub until city-order
  // capability table is typed on TGreatPower.
}

// FUNCTION: IMPERIALISM 0x0052fba0
void TForeignMinister::DispatchProposalSlot98(int arg1, int arg2, int arg3, int targetNation) {
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
  // RunForeignMinisterAmountDispatchShared — amount clamp/dispatch; stub pending.
}

// FUNCTION: IMPERIALISM 0x0052fcc0
void TForeignMinister::RecomputeOrderStateSlot9C() {
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x12) = 0;
  *reinterpret_cast<short*>(raw + 0x14) = 0;
  *reinterpret_cast<short*>(raw + 0x10) = static_cast<short>(0xfff6);
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

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
