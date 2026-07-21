#include "game/TDefenseMinister.h"

#include <string.h>

#include "game/global_data_tables.h"

#include "game/CIterator.h"
#include "game/mfc.h"
#include "game/TAutoGreatPower.h"
#include "game/TGreatPower.h"
#include "game/TLongintList.h"
#include "game/TMapMgr.h"
#include "game/TStream.h"
#include "game/TMission.h"
#include "game/ui_invalidation_guard.h"

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
unsigned char*
TDefenseMinister::BuildTileRingPriorityMapForNationTileList(TLongintList* ownedRegions) {
  int ownNationSlot = ownerContextAt04->nationSlot;
  int regionCount = ownedRegions->GetSize();

  unsigned char* priorityMap = new unsigned char[0x1950];
  if (priorityMap == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x1a9);
  }
  memset(priorityMap, 0, 0x1950);

  short neighbors[6];
  char wrapHorizontally = g_pGlobalMapState->hexNeighborWrapHorizontally20;

  // Pass 1: mark regions bordering foreign-owned territory with priority 4.
  for (int i = 1; i <= regionCount; ++i) {
    short regionId = static_cast<short>(ownedRegions->At(i));
    TMapMgr::ComputeHexNeighborTileIndices(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      int neighborOwner = g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      if (neighborOwner > 0 && neighborOwner != ownNationSlot) {
        priorityMap[regionId] = 4;
      }
    }
  }

  // Pass 2: mark regions bordering a priority-4 tile with priority 3.
  for (int i2 = 1; i2 <= regionCount; ++i2) {
    short regionId = static_cast<short>(ownedRegions->At(i2));
    TMapMgr::ComputeHexNeighborTileIndices(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      if (priorityMap[neighborTile] == 4) {
        priorityMap[regionId] = 3;
      }
    }
  }

  // Pass 3: mark regions bordering a priority-3 tile, or a terrainType00==5 tile, with
  // priority 2.
  for (int i3 = 1; i3 <= regionCount; ++i3) {
    short regionId = static_cast<short>(ownedRegions->At(i3));
    TMapMgr::ComputeHexNeighborTileIndices(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      if (priorityMap[neighborTile] == 3 ||
          g_pGlobalMapState->terrainStateTable[neighborTile].terrainType00 == 5) {
        priorityMap[regionId] = 2;
      }
    }
  }

  // Pass 4: mark regions bordering a priority-2 tile with priority 1.
  for (int i4 = 1; i4 <= regionCount; ++i4) {
    short regionId = static_cast<short>(ownedRegions->At(i4));
    TMapMgr::ComputeHexNeighborTileIndices(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      if (priorityMap[neighborTile] == 2) {
        priorityMap[regionId] = 1;
      }
    }
  }

  // Pass 5: for regions with a qualifying activeFlags1c/resourceTypeByEdge[1] combination,
  // boost this region's priority by 3 and each prospecting-eligible neighbor's by 1.
  for (int i5 = 1; i5 <= regionCount; ++i5) {
    short regionId = static_cast<short>(ownedRegions->At(i5));
    TTerrainStateRecordView* record = &g_pGlobalMapState->terrainStateTable[regionId];
    if ((record->activeFlags1c & 3) == 0 || record->resourceTypeByEdge[1] == 0) {
      continue;
    }
    priorityMap[regionId] += 3;

    TMapMgr::ComputeHexNeighborTileIndices(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      if (g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(neighborTile)) {
        ++priorityMap[neighborTile];
      }
    }
  }

  return priorityMap;
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
