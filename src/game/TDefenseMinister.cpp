#include "game/TDefenseMinister.h"

#include "game/CIterator.h"
#include "game/CRuntimeClass.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TTrackedObject.h"

extern "C" {
CRuntimeClass g_pClassDescTDefenseMinister = {nullptr, 0, 0, nullptr, nullptr};
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// Slot 24 (0x60) — body 0x4ec0a0; placed first because it is the lowest address.
// FUNCTION: IMPERIALISM 0x004ec0a0
void TDefenseMinister::DefenseSlot18() {}

// MFC RTTI slot 0x00 override: returns this class's CRuntimeClass descriptor (0x654838).
// FUNCTION: IMPERIALISM 0x004ec0c0
CRuntimeClass* TDefenseMinister::GetRuntimeClass() {
  return &g_pClassDescTDefenseMinister;
}

// FUNCTION: IMPERIALISM 0x004ec0e0
TDefenseMinister::TDefenseMinister() : TMinister() {}

// Destructor is compiler-generated (implicit) from real TMinister inheritance.
// SYNTHETIC: IMPERIALISM 0x004ec110
// TDefenseMinister::`scalar deleting destructor'

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

// Slot 5 override (0x4ec1d0): serialize defense-minister order-array metrics.
// Honest stub — body not yet ported (needs the defense field layout data pass).
// FUNCTION: IMPERIALISM 0x004ec1d0
void TDefenseMinister::SerializeTMinisterBaseOrderArrayHeader(TStream* archive) {
  (void)archive;
}

// Slot 6 override (0x4ec2f0): deserialize defense-minister order-array metrics.
// FUNCTION: IMPERIALISM 0x004ec2f0
void TDefenseMinister::Call18(int arg1) {
  (void)arg1;
}

// Slot 10 override (0x4ec3d0).
// FUNCTION: IMPERIALISM 0x004ec3d0
void TDefenseMinister::MinisterSlot0A() {}

// Slot 18 override (0x4ec450).
// FUNCTION: IMPERIALISM 0x004ec450
void TDefenseMinister::MinisterSlot12() {}

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

// Slot 20 override (0x4ec540).
// FUNCTION: IMPERIALISM 0x004ec540
void TDefenseMinister::MinisterSlot14() {}

// Slot 21 override (0x4ecbb0).
// FUNCTION: IMPERIALISM 0x004ecbb0
void TDefenseMinister::Call54() {}

// Slot 22 (0x58) — body 0x4ecf20.
// FUNCTION: IMPERIALISM 0x004ecf20
void TDefenseMinister::DefenseSlot16() {}

// Slot 23 (0x5c) — body 0x4ed050.
// FUNCTION: IMPERIALISM 0x004ed050
void TDefenseMinister::DefenseSlot17() {}

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif
