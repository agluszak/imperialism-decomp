#include "game/TDefenseMinister.h"

#include "game/global_data_tables.h"

#include "game/CIterator.h"
#include "game/mfc.h"
#include "game/TAutoGreatPower.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TMission.h"

// Slot 24 (0x60) — body 0x4ec0a0; placed first because it is the lowest address.

// FUNCTION: IMPERIALISM 0x004ec0a0
double TDefenseMinister::GetPersonalityWeightByFlag(char) {
  return g_DefenseMinisterWeightZero_006548E0;
}
// SYNTHETIC: IMPERIALISM 0x004ec020
// TDefenseMinister::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ec0c0
// TDefenseMinister::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDefenseMinister, TMinister)

// FUNCTION: IMPERIALISM 0x004ec0e0
TDefenseMinister::TDefenseMinister() : TMinister() {}

// Destructor is compiler-generated (implicit) from real TMinister inheritance.

// SYNTHETIC: IMPERIALISM 0x004ec110
// TDefenseMinister::`scalar deleting destructor'
TDefenseMinister::~TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004ec160
void TDefenseMinister::InitializeBaseOrderArrayMetrics(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    orderWeightTableA[i] = 0;
  }
}

// Slot 5 override (0x4ec1d0): serialize defense-minister order-array metrics.

// FUNCTION: IMPERIALISM 0x004ec1d0
void TDefenseMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  stream->WriteBytesSlot78(&field10, 2);
  stream->WriteBytesSlot78(&field12, 2);
  short* cursor = orderWeightTableA;
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
  cursor = orderWeightTableB;
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
  stream->WriteBytesSlot78(&thresholdA, 2);
  stream->WriteBytesSlot78(&thresholdB, 2);
  stream->WriteBytesSlot78(&thresholdC, 2);
  stream->WriteBytesSlot78(&thresholdD, 2);
}

// Slot 6 override (0x4ec2f0): deserialize defense-minister order-array metrics.

// FUNCTION: IMPERIALISM 0x004ec2f0
void TDefenseMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  stream->ReadBytes(&field10, 2);
  stream->ReadBytes(&field12, 2);
  stream->ReadBytes(orderWeightTableA, 0x3c);
  unsigned char* pairCursor = reinterpret_cast<unsigned char*>(orderWeightTableA);
  int pairCount = 0x1e;
  do {
    unsigned char highByte = pairCursor[0];
    pairCursor[0] = pairCursor[1];
    pairCursor[1] = highByte;
    pairCursor = pairCursor + 2;
    pairCount = pairCount - 1;
  } while (pairCount != 0);
  stream->ReadBytes(orderWeightTableB, 0x3c);
  pairCursor = reinterpret_cast<unsigned char*>(orderWeightTableB);
  pairCount = 0x1e;
  do {
    unsigned char highByte = pairCursor[0];
    pairCursor[0] = pairCursor[1];
    pairCursor[1] = highByte;
    pairCursor = pairCursor + 2;
    pairCount = pairCount - 1;
  } while (pairCount != 0);
  stream->ReadBytes(&thresholdA, 2);
  stream->ReadBytes(&thresholdB, 2);
  stream->ReadBytes(&thresholdC, 2);
  stream->ReadBytes(&thresholdD, 2);
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
  // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
  TAutoGreatPower* owner = reinterpret_cast<TAutoGreatPower*>(this->ownerContextAt04);
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
undefined TDefenseMinister::BuildTileRingPriorityMapForNationTileList(int*) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ecf20
undefined TDefenseMinister::BuildStrategicTilePriorityHeatmap() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ed050
undefined TDefenseMinister::BuildHexAreaTileIndexListIntoAllocatedBuffer(char) {
  return 0;
}

// Five personality-specific order-array initializers (0x4ed560/0x4ed890/0x4edb80/
// 0x4ede60/0x4ee150) called from TNapoleonMinister/TBismarckMinister/TPirateMinister/
// TDefenderMinister/TBullyMinister's own construction. Each duplicates
// InitializeBaseOrderArrayMetrics's zeroing prefix inline (the original has no shared
// call between them -- every one of the six addresses inlines its own copy), then
// seeds its own thresholdA-D quad and orderWeightTableB[2]/[4]/[7] prefix.

// FUNCTION: IMPERIALISM 0x004ed560
void TDefenseMinister::InitializeOrderArrayPreset50_0_10_50(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    orderWeightTableA[i] = 0;
  }
  thresholdC = 10;
  thresholdA = 0x32;
  thresholdB = 0;
  orderWeightTableB[2] = 0x23;
  orderWeightTableB[7] = 0x37;
  orderWeightTableB[4] = 0x5a;
  thresholdD = 0x32;
}

// FUNCTION: IMPERIALISM 0x004ed890
void TDefenseMinister::InitializeOrderArrayPreset10_10_10_50(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    orderWeightTableA[i] = 0;
  }
  orderWeightTableB[2] = 0x23;
  thresholdA = 10;
  thresholdB = 10;
  thresholdC = 10;
  orderWeightTableB[7] = 0x37;
  orderWeightTableB[4] = 0x5a;
  thresholdD = 0x32;
}

// FUNCTION: IMPERIALISM 0x004edb80
void TDefenseMinister::InitializeOrderArrayPreset15_20_50_75(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    orderWeightTableA[i] = 0;
  }
  thresholdA = 0xf;
  thresholdB = 0x14;
  thresholdC = 0x32;
  orderWeightTableB[2] = 0x4b;
  orderWeightTableB[7] = 100;
  orderWeightTableB[4] = 0x6e;
  thresholdD = 0x4b;
}

// FUNCTION: IMPERIALISM 0x004ede60
void TDefenseMinister::InitializeOrderArrayPreset20_10_10_50(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    orderWeightTableA[i] = 0;
  }
  thresholdA = 0x14;
  thresholdB = 10;
  thresholdC = 10;
  orderWeightTableB[2] = 0x4b;
  orderWeightTableB[7] = 100;
  orderWeightTableB[4] = 0x6e;
  thresholdD = 0x32;
}

// FUNCTION: IMPERIALISM 0x004ee150
void TDefenseMinister::InitializeOrderArrayPreset25_10_20_50(TGreatPower* owner) {
  this->InitializeBaseOrderArray(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    orderWeightTableA[i] = 0;
  }
  thresholdA = 0x19;
  thresholdB = 10;
  thresholdC = 0x14;
  orderWeightTableB[2] = 0x23;
  orderWeightTableB[7] = 0x37;
  orderWeightTableB[4] = 0x5a;
  thresholdD = 0x32;
}
