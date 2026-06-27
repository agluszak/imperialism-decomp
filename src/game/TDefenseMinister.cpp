#include "game/TDefenseMinister.h"

#include "game/CIterator.h"
#include "game/mfc.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TMission.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// Slot 24 (0x60) — body 0x4ec0a0; placed first because it is the lowest address.

// FUNCTION: IMPERIALISM 0x004ec0a0
undefined TDefenseMinister::CreateTDefenseMinisterInstance() { return 0; }
IMPLEMENT_DYNCREATE(TDefenseMinister, TMinister)

// FUNCTION: IMPERIALISM 0x004ec0e0
TDefenseMinister::TDefenseMinister() : TMinister() {}

// Destructor is compiler-generated (implicit) from real TMinister inheritance.

// SYNTHETIC: IMPERIALISM 0x004ec110
// TDefenseMinister::`scalar deleting destructor'
TDefenseMinister::~TDefenseMinister() {}

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

// FUNCTION: IMPERIALISM 0x004ec1d0
void TDefenseMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  char* raw = reinterpret_cast<char*>(this);
  stream->WriteBytesSlot78(raw + 0x10, 2);
  stream->WriteBytesSlot78(raw + 0x12, 2);
  short* cursor = reinterpret_cast<short*>(raw + 0x14);
  int remaining = 0x1e;
  do {
    unsigned int stackWord = static_cast<unsigned int>(*cursor);
    unsigned char* stackBytes = reinterpret_cast<unsigned char*>(&stackWord);
    unsigned char lowByte = stackBytes[0];
    stackBytes[0] = stackBytes[1];
    stackBytes[1] = lowByte;
    stream->WriteBytesSlot78(&stackWord, 2);
    cursor = cursor + 1;
    remaining = remaining - 1;
  } while (remaining != 0);
  cursor = reinterpret_cast<short*>(raw + 0x50);
  remaining = 0x1e;
  do {
    unsigned int stackWord = static_cast<unsigned int>(*cursor);
    unsigned char* stackBytes = reinterpret_cast<unsigned char*>(&stackWord);
    unsigned char lowByte = stackBytes[0];
    stackBytes[0] = stackBytes[1];
    stackBytes[1] = lowByte;
    stream->WriteBytesSlot78(&stackWord, 2);
    cursor = cursor + 1;
    remaining = remaining - 1;
  } while (remaining != 0);
  stream->WriteBytesSlot78(raw + 0x8c, 2);
  stream->WriteBytesSlot78(raw + 0x8e, 2);
  stream->WriteBytesSlot78(raw + 0x90, 2);
  stream->WriteBytesSlot78(raw + 0x92, 2);
}

// Slot 6 override (0x4ec2f0): deserialize defense-minister order-array metrics.

// FUNCTION: IMPERIALISM 0x004ec2f0
void TDefenseMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  char* raw = reinterpret_cast<char*>(this);
  stream->ReadBytes(raw + 0x10, 2);
  stream->ReadBytes(raw + 0x12, 2);
  stream->ReadBytes(raw + 0x14, 0x3c);
  unsigned char* pairCursor = reinterpret_cast<unsigned char*>(raw + 0x14);
  int pairCount = 0x1e;
  do {
    unsigned char highByte = pairCursor[0];
    pairCursor[0] = pairCursor[1];
    pairCursor[1] = highByte;
    pairCursor = pairCursor + 2;
    pairCount = pairCount - 1;
  } while (pairCount != 0);
  stream->ReadBytes(raw + 0x50, 0x3c);
  pairCursor = reinterpret_cast<unsigned char*>(raw + 0x50);
  pairCount = 0x1e;
  do {
    unsigned char highByte = pairCursor[0];
    pairCursor[0] = pairCursor[1];
    pairCursor[1] = highByte;
    pairCursor = pairCursor + 2;
    pairCount = pairCount - 1;
  } while (pairCount != 0);
  stream->ReadBytes(raw + 0x8c, 2);
  stream->ReadBytes(raw + 0x8e, 2);
  stream->ReadBytes(raw + 0x90, 2);
  stream->ReadBytes(raw + 0x92, 2);
}

// Slot 10 override (0x4ec3d0).

// FUNCTION: IMPERIALISM 0x004ec3d0
short TDefenseMinister::DispatchNationStateEventCode10(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ec450
void TDefenseMinister::MinisterSlot12() {}

// FUNCTION: IMPERIALISM 0x004ec4c0
void TDefenseMinister::Call4C() {
  TGreatPower* owner = reinterpret_cast<TGreatPower*>(this->ownerContextAt04);
  owner->AssertValid();
  CIterator missionCursor(owner->missionQueue);
  TMission* mission = static_cast<TMission*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    mission->MissionSlot44();
    mission = static_cast<TMission*>(missionCursor.Advance());
  }
}

// Slot 20 override (0x4ec540).

// FUNCTION: IMPERIALISM 0x004ec540
void TDefenseMinister::MinisterSlot14() {}

// Slot 21 override (0x4ecbb0).

// FUNCTION: IMPERIALISM 0x004ecbb0
undefined TDefenseMinister::BuildTileRingPriorityMapForNationTileList() { return 0; }

// FUNCTION: IMPERIALISM 0x004ecf20
undefined TDefenseMinister::BuildStrategicTilePriorityHeatmap() { return 0; }

// FUNCTION: IMPERIALISM 0x004ed050
undefined TDefenseMinister::BuildHexAreaTileIndexListIntoAllocatedBuffer() { return 0; }
