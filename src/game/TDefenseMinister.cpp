#include "game/TDefenseMinister.h"

#include "game/CIterator.h"
#include "game/TGreatPower.h"
#include "game/TTrackedObject.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x004ec0e0
TDefenseMinister::TDefenseMinister() : TMinister() {}

// FUNCTION: IMPERIALISM 0x004ec160
void TDefenseMinister::InitializeBaseOrderArrayMetrics() {
  this->InitializeBaseOrderArray(0);
  char* raw = reinterpret_cast<char*>(this);
  *reinterpret_cast<short*>(raw + 0x10) = 0;
  *reinterpret_cast<short*>(raw + 0x12) = 0;
  *reinterpret_cast<short*>(raw + 0x8c) = 0;
  *reinterpret_cast<short*>(raw + 0x8e) = 0;
  *reinterpret_cast<short*>(raw + 0x90) = 0;
  *reinterpret_cast<short*>(raw + 0x92) = 0;
  short* cursor = reinterpret_cast<short*>(raw + 0x14);
  int remaining = 0x1e;
  do {
    cursor[0x1e] = 0;
    *cursor = 0;
    ++cursor;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x004ec4c0
void TDefenseMinister::Call4C() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);
  owner->VTableIndex03_Provisional();
  CIterator missionCursor(owner->missionQueue);
  TTrackedObject* mission = static_cast<TTrackedObject*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    mission->MissionSlot44();
    mission = static_cast<TTrackedObject*>(missionCursor.Advance());
  }
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
