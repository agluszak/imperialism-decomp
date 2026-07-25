#include "game/military_ui/TDefenseMinister.h"

#include <stdlib.h>
#include <string.h>

#include "game/globals/prelude.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/shared_globals.h"

#include "game/ui_core/CIterator.h"
#include "game/mfc.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/TList.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/city_ui/TLongintList.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/core/TStream.h"
#include "game/map/TMission.h"
#include "game/military/TUnit.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_screens/TSimMgr.h"

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
// FUNCTION: IMPERIALISM 0x004ec140
TDefenseMinister::~TDefenseMinister() {}

// FUNCTION: IMPERIALISM 0x004ec160
void TDefenseMinister::InitializeBaseOrderArrayMetrics(TGreatPower* owner) {
  this->IMinister(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    recruitOrderCountByType[i] = 0;
  }
}

// Slot 5 override (0x4ec1d0): serialize defense-minister order-array metrics.

// FUNCTION: IMPERIALISM 0x004ec1d0
void TDefenseMinister::WriteTo(TStream* stream) {
  TMinister::WriteTo(stream);
  stream->WriteBytes(&field10, 2);
  stream->WriteBytes(&field12, 2);
  short* cursor = recruitOrderCountByType;
  int remaining = 0x1e;
  do {
    unsigned int stackWord = static_cast<unsigned int>(*cursor);
    unsigned char* stackBytes = reinterpret_cast<unsigned char*>(&stackWord);
    unsigned char lowByte = stackBytes[0];
    stackBytes[0] = stackBytes[1];
    stackBytes[1] = lowByte;
    stream->WriteBytes(&stackWord, 2);
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
    stream->WriteBytes(&stackWord, 2);
    cursor = cursor + 1;
    remaining = remaining - 1;
  } while (remaining != 0);
  stream->WriteBytes(&thresholdA, 2);
  stream->WriteBytes(&thresholdB, 2);
  stream->WriteBytes(&thresholdC, 2);
  stream->WriteBytes(&thresholdD, 2);
}

// Slot 6 override (0x4ec2f0): deserialize defense-minister order-array metrics.

// FUNCTION: IMPERIALISM 0x004ec2f0
void TDefenseMinister::ReadFrom(TStream* stream) {
  TMinister::ReadFrom(stream);
  stream->ReadBytes(&field10, 2);
  stream->ReadBytes(&field12, 2);
  stream->ReadBytes(recruitOrderCountByType, 0x3c);
  unsigned char* pairCursor = reinterpret_cast<unsigned char*>(recruitOrderCountByType);
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
short TDefenseMinister::GetRankingCriterionForGP(short nationSlot) {
  (void)nationSlot;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ec450
void TDefenseMinister::GoShopping() {
  if (g_pSimMgr->GetEconomicTurn() > 6 && rand() % 100 < 33) {
    ownerContextAt04->interiorMinister->PleaseBuildLandUnit(static_cast<short>(rand() % 7 + 1));
  }
}

// FUNCTION: IMPERIALISM 0x004ec4c0
void TDefenseMinister::DoArmyMovement() {
  // See TAttackProvinceMission::Free: the tail AI state block is TAutoGreatPower-only.
  TAutoGreatPower* owner = static_cast<TAutoGreatPower*>(ownerContextAt04);
  owner->AssertValid();
  CIterator missionCursor(owner->missionQueue);
  TMission* mission = static_cast<TMission*>(missionCursor.Reset());
  while (missionCursor.More() != 0) {
    mission->GiveOrders();
    mission = static_cast<TMission*>(missionCursor.Advance());
  }
}

// Slot 20 override (0x4ec540).

// FUNCTION: IMPERIALISM 0x004ec540
void TDefenseMinister::DoPeacetimeDeployment() {
  TGreatPower* owner = ownerContextAt04;
  int totalUnitCount = owner->militaryUnitList44->GetCount();

  TCity* city = owner ? owner->city : 0;
  short homeTileId = city->SelectedOrderTileId();

  short ownNationSlot = owner->nationSlot;

  TLongintList* ownedRegionsList = new TLongintList();
  for (int tile = 0; tile < 0x1950; ++tile) {
    if (g_pGlobalMapState->terrainStateTable[tile].ownerNationTag04 == ownNationSlot) {
      ownedRegionsList->InsertLast(tile);
    }
  }

  unsigned char* priorityMap = this->BuildTileRingPriorityMapForNationTileList(ownedRegionsList);

  TList* bucket1 = new TList();
  if (bucket1 == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x12f);
  }

  TList* bucket2 = new TList();
  if (bucket2 == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x130);
  }

  TList* bucket3 = new TList();
  if (bucket3 == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x131);
  }

  TSortedList* militaryUnitList = owner->militaryUnitList44;
  for (int unitOrdinal = 1; unitOrdinal <= totalUnitCount; ++unitOrdinal) {
    TUnit* unit = static_cast<TUnit*>(militaryUnitList->GetEntryByOrdinal(unitOrdinal));
    if (unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitRegulars)) {
      bucket1->AddTail(unit);
    } else if (unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitArtillery)) {
      bucket2->AddTail(unit);
    } else if (unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitLightArtillery)) {
      bucket2->AddTail(unit);
    } else {
      bucket3->AddTail(unit);
    }
  }

  int bucket1Count = bucket1->GetCount();
  int n = bucket1Count / 2;
  int trimCount = (n < 3) ? bucket1->GetCount() : 4;
  for (; trimCount > 0; --trimCount) {
    int idx = bucket1->GetCount();
    TUnit* unit = static_cast<TUnit*>(bucket1->GetEntryByOrdinal(idx));
    unit->MoveTo(homeTileId);
    bucket1->RemoveAtOrdinal(idx);
  }

  if (bucket2->GetCount() != 0) {
    int idx = bucket2->GetCount();
    TUnit* unit = static_cast<TUnit*>(bucket2->GetEntryByOrdinal(idx));
    unit->MoveTo(homeTileId);
    bucket2->RemoveAtOrdinal(idx);
  }

  n -= 2;
  if (n > 0) {
    short* scratchBuf = new short[n];
    if (scratchBuf == nullptr) {
      FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x15e);
    }

    for (int fillIdx = 1; fillIdx <= n; ++fillIdx) {
      scratchBuf[fillIdx - 1] = static_cast<short>(ownedRegionsList->At(fillIdx));
    }

    int regionCount = ownedRegionsList->GetSize();
    for (int i2 = 1; i2 <= regionCount; ++i2) {
      short regionId = static_cast<short>(ownedRegionsList->At(i2));
      short bestPriority = static_cast<signed char>(priorityMap[regionId]);
      for (int j = 0; j < n; ++j) {
        short scratchRegionId = scratchBuf[j];
        short candidatePriority = static_cast<signed char>(priorityMap[scratchRegionId]);
        if (candidatePriority < bestPriority) {
          scratchBuf[j] = regionId;
          bestPriority = candidatePriority;
          regionId = scratchRegionId;
        }
      }
    }

    for (int k = 0; k < n; ++k) {
      short regionId = scratchBuf[k];
      for (int u = 0; u < 2; ++u) {
        int idx = bucket1->GetCount();
        TUnit* unit = static_cast<TUnit*>(bucket1->GetEntryByOrdinal(idx));
        unit->MoveTo(regionId);
        bucket1->RemoveAtOrdinal(idx);
      }
      if (bucket2->GetCount() != 0) {
        int idx = bucket2->GetCount();
        TUnit* unit = static_cast<TUnit*>(bucket2->GetEntryByOrdinal(idx));
        unit->MoveTo(regionId);
        bucket2->RemoveAtOrdinal(idx);
      }
    }
    // Note: the original never frees scratchBuf (leaked), matching its exact allocation
    // pattern here.
  }

  bucket1->Free();
  bucket2->Free();
  bucket3->Free();
  delete[] priorityMap;
  ownedRegionsList->Free();
}

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
    TMapMgr::GetNeighborTileIDArray(regionId, neighbors, wrapHorizontally);
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
    TMapMgr::GetNeighborTileIDArray(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      if (priorityMap[neighborTile] == 4) {
        priorityMap[regionId] = 3;
      }
    }
  }

  // Pass 3: mark regions bordering a priority-3 tile, or a water tile, with
  // priority 2.
  for (int i3 = 1; i3 <= regionCount; ++i3) {
    short regionId = static_cast<short>(ownedRegions->At(i3));
    TMapMgr::GetNeighborTileIDArray(regionId, neighbors, wrapHorizontally);
    for (int dir = 0; dir < 6; ++dir) {
      short neighborTile = neighbors[dir];
      if (priorityMap[neighborTile] == 3 ||
          g_pGlobalMapState->terrainStateTable[neighborTile].GetTerrainKind() ==
              kStrategicTerrainWater) {
        priorityMap[regionId] = 2;
      }
    }
  }

  // Pass 4: mark regions bordering a priority-2 tile with priority 1.
  for (int i4 = 1; i4 <= regionCount; ++i4) {
    short regionId = static_cast<short>(ownedRegions->At(i4));
    TMapMgr::GetNeighborTileIDArray(regionId, neighbors, wrapHorizontally);
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

    TMapMgr::GetNeighborTileIDArray(regionId, neighbors, wrapHorizontally);
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
int* TDefenseMinister::BuildStrategicTilePriorityHeatmap() {
  short ownNationSlot = ownerContextAt04->nationSlot;

  int* heatmap = new int[0x1950];
  memset(heatmap, 0, 0x1950 * sizeof(int));

  for (int tile = 0; tile < 0x1950; ++tile) {
    TTerrainStateRecordView* record = &g_pGlobalMapState->terrainStateTable[tile];
    if (record->ownerNationTag04 == ownNationSlot) {
      if ((record->activeFlags1c & 3) != 0 && record->gateFlag != 0) {
        heatmap[tile] += 300;

        short* ring1 = BuildHexAreaTileIndexList(static_cast<short>(tile), 1);
        for (int dir = 0; dir < 6; ++dir) {
          heatmap[ring1[dir]] += 200;
        }
        delete[] ring1;

        short* ring2 = BuildHexAreaTileIndexList(static_cast<short>(tile), 2);
        for (int dir2 = 0; dir2 < 12; ++dir2) {
          heatmap[ring2[dir2]] += 100;
        }
        delete[] ring2;
      }
    } else if (record->adjacencyBits06 != 0) {
      heatmap[tile] += 100;
    }
  }

  return heatmap;
}

// FUNCTION: IMPERIALISM 0x004ed050
int* TDefenseMinister::BuildHexAreaTileIndexListIntoAllocatedBuffer(char excludeEnemyTiles) {
  short ownNationSlot = ownerContextAt04->nationSlot;

  bool atWarWithNation[0x17];
  for (int nation = 0; nation < 0x17; ++nation) {
    atWarWithNation[nation] = g_pDiplomacyTurnStateManager->IsNationPairAtWar(
                                  ownNationSlot, static_cast<short>(nation)) != 0;
  }

  int* weightSum = new int[0x1950];
  if (weightSum == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x24a);
  }

  int* maxWeight = new int[0x1950];
  if (weightSum == nullptr) {
    FailNilPointerWithAssert(s_SourcePathUDefenseMinister_00696860, 0x24e);
  }

  for (int fillIdx = 0; fillIdx < 0x1950; ++fillIdx) {
    weightSum[fillIdx] = 0;
    maxWeight[fillIdx] = 1;
  }

  for (int tile = 0; tile < 0x1950; ++tile) {
    TTerrainStateRecordView* record = &g_pGlobalMapState->terrainStateTable[tile];
    short ownerTag = record->ownerNationTag04;
    if ((atWarWithNation[ownerTag] && excludeEnemyTiles == 0) || ownerTag == ownNationSlot) {
      TMilitaryUnit* unit;
      if (tile >= 0 && tile < 0x180) {
        unit = static_cast<TMilitaryUnit*>(
            g_pGlobalMapState->cityScoreTable[tile].stationedUnitChain98);
      } else {
        unit = 0;
      }

      if (unit->field_18 != ownNationSlot) {
        int categoryScores[4] = {0, 0, 0, 0};
        int categoryFlags[4] = {1, 1, 1, 1};

        for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextOnTile)) {
          short combatClass = g_awUnitCombatClassBySlot[unit->orderType];
          if (unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitLightArtillery) ||
              unit->orderType == EncodeMilitaryUnitKind(kMilitaryUnitArtillery)) {
            if (combatClass >= 0) {
              for (int k = 0; k <= combatClass; ++k) {
                categoryFlags[k] = 2;
              }
            }
          } else {
            int weightedValue =
                g_anUnitStrengthWeightPercentBySlot[unit->orderType] * unit->field_34 / 100;
            if (combatClass >= 0) {
              for (int k = 0; k <= combatClass; ++k) {
                categoryScores[k] += weightedValue;
              }
            }
          }
        }

        weightSum[tile] += categoryScores[0];
        if (maxWeight[tile] < categoryFlags[0]) {
          maxWeight[tile] = categoryFlags[0];
        }

        for (int radius = 1; radius <= 3; ++radius) {
          short* ring =
              BuildHexAreaTileIndexList(static_cast<short>(tile), static_cast<short>(radius));
          int weightVal = categoryScores[radius];
          int flagVal = categoryFlags[radius];
          for (int dir = 0; dir < radius * 6; ++dir) {
            weightSum[ring[dir]] += weightVal;
            if (maxWeight[ring[dir]] < flagVal) {
              maxWeight[ring[dir]] = flagVal;
            }
          }
        }
      }
    }
  }

  for (int i = 0; i < 0x1950; ++i) {
    if (weightSum[0] != 0 && maxWeight[i] > 1) {
      weightSum[0] = maxWeight[i] * weightSum[0];
    }
  }

  delete[] maxWeight;
  return weightSum;
}

// Five personality-specific order-array initializers (0x4ed560/0x4ed890/0x4edb80/
// 0x4ede60/0x4ee150) called from TNapoleonMinister/TBismarckMinister/TPirateMinister/
// TDefenderMinister/TBullyMinister's own construction. Each duplicates
// InitializeBaseOrderArrayMetrics's zeroing prefix inline (the original has no shared
// call between them -- every one of the six addresses inlines its own copy), then
// seeds its own thresholdA-D quad and orderWeightTableB[2]/[4]/[7] prefix.

// FUNCTION: IMPERIALISM 0x004ed560
void TDefenseMinister::InitializeOrderArrayPreset50_0_10_50(TGreatPower* owner) {
  this->IMinister(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    recruitOrderCountByType[i] = 0;
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
  this->IMinister(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    recruitOrderCountByType[i] = 0;
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
  this->IMinister(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    recruitOrderCountByType[i] = 0;
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
  this->IMinister(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    recruitOrderCountByType[i] = 0;
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
  this->IMinister(owner);
  field10 = 0;
  field12 = 0;
  thresholdA = 0;
  thresholdB = 0;
  thresholdC = 0;
  thresholdD = 0;
  for (int i = 0; i < 0x1e; ++i) {
    orderWeightTableB[i] = 0;
    recruitOrderCountByType[i] = 0;
  }
  thresholdA = 0x19;
  thresholdB = 10;
  thresholdC = 0x14;
  orderWeightTableB[2] = 0x23;
  orderWeightTableB[7] = 0x37;
  orderWeightTableB[4] = 0x5a;
  thresholdD = 0x32;
}
