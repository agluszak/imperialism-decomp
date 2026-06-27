#include "game/TMapMgr.h"

#include "game/CString.h"
#include "game/TSortedList.h"
#include "game/TMinor.h"
#include "game/TCivUnit.h"
#include "game/TPortZone.h"
#include "game/TOcean.h"
#include "game/TZone.h"
#include "game/diplomacy_globals.h"

void EnsurePortZoneForTile(short nTileIndex);
void RemovePortZoneByTile(short nTileIndex);
short TraceTerrainFlowToNearestSeaTile(short tileIndex);

#pragma optimize("y", on)

extern "C" {
extern short g_Build_Hex_Area_LookupTable_00696E70[];
extern short g_Build_Hex_Area_LookupTable_00696E80[];
short __cdecl GetHexDirectionBetweenTiles(short sourceTile, short destTile) {
  typedef short (__cdecl *Func)(short, short);
  return reinterpret_cast<Func>(0x00512dd0)(sourceTile, destTile);
}
}
IMPLEMENT_DYNCREATE(TMapMgr, TObject)

TMapMgr::TMapMgr() {}

TMapMgr::~TMapMgr() {}

void TMapMgr::Free() {}

void TMapMgr::ReadFrom(TStream* stream) {}

void TMapMgr::WriteTo(TStream* stream) {}

undefined TMapMgr::WrapperFor_AllocateWithFallbackHandler_At0050e8b0() { return 0; }

undefined TMapMgr::BuildOrLoadGlobalMapStateForSession(CString param_1, char * param_2) { return 0; }

undefined TMapMgr::LoadPoliticalMapRegionSubtypeTableFromResourceStream() { return 0; }

undefined TMapMgr::UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(int param_1) { return 0; }

undefined TMapMgr::UpdateTileNeighborBorderInfluenceCounters(short param_1, short param_2) { return 0; }

undefined TMapMgr::UpdateMapTileAdjacencyMasksAndVariantForTile(uint param_1) { return 0; }

undefined TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded(int param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins01_00511610(short param_1) { return 0; }

undefined TMapMgr::TMapMaker_EnsureRegionClassHasSubtype3And4AssignmentsWithRng() { return 0; }

undefined TMapMgr::TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress() { return 0; }

undefined TMapMgr::DispatchTurnEvent7DDForActiveNation() { return 0; }

undefined TMapMgr::ForwardComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(undefined4 param_1) {
  ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(static_cast<short>(param_1), 1);
  return 0;
}

undefined TMapMgr::TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(short param_1, short param_2) { return 0; }

undefined TMapMgr::IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(int param_1, short param_2) { return 0; }

undefined TMapMgr::IsShiftKeyDown() { return 0; }

undefined TMapMgr::IsAltKeyDown() { return 0; }

undefined TMapMgr::OrphanCallChain_C3_I43_00513170(short param_1) { return 0; }

undefined TMapMgr::DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(short param_1, undefined4 param_2) { return 0; }

undefined TMapMgr::SetTileOwnerAndInvalidateNeighborState(short param_1, short param_2) { return 0; }

undefined TMapMgr::OrphanCallChain_C1_I29_005135a0(short param_1, char param_2) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins14_00513610(short param_1, short param_2) { return 0; }

byte TMapMgr::GetTileCivilianWorkOrderCostClassNibble(short nTileIndex, char fUseHighNibble) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins35_005136a0(short param_1, char param_2, byte param_3, char param_4) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins37_00513720(short param_1, char param_2, int param_3) { return 0; }

undefined TMapMgr::SetHexAdjacencyDirectionFlagsForTilePair(short param_1, short param_2) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins18_00514310(short param_1, short param_2) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins31_00514360(short param_1, short param_2, short param_3) { return 0; }

void TMapMgr::FloodFillTileRegionMarker(short nTileIndex, short nOwnerNationId) {}

int TMapMgr::QueueDepotConstructionOrder(int * pMapContext, short nTileIndex, short nNationId, undefined2 param_4) { return 0; }

void TMapMgr::QueuePortConstructionOrder(int * pMapContext, short nTileIndex, short nNationId, undefined2 param_4) {}

void TMapMgr::SetProvinceCapitalTileFlagBit08(short nProvinceId) {}

void TMapMgr::SetTileTransportFlagsTo0x37AndRefreshNeighbors(short nTileIndex) {}

undefined TMapMgr::WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins15_00514e40(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins28_00514e80() { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins09_00514ef0() { return 0; }

undefined TMapMgr::OrphanCallChain_C5_I115_00514f20(int param_1) { return 0; }

undefined TMapMgr::OrphanCallChain_C1_I159_005150e0(int * param_1, short param_2) { return 0; }

undefined TMapMgr::WrapperFor_LookupOrderCompatibilityMatrixValue_At00515330(int param_1) { return 0; }

undefined TMapMgr::WrapperFor_LookupOrderCompatibilityMatrixValue_At00515460(int param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins83_005155c0(int param_1) { return 0; }

undefined TMapMgr::MarkType5NeighborTilesUnavailableByNationCapability(int param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins69_00515890(int param_1) { return 0; }

undefined TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA(int param_1) { return 0; }

undefined TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB(int param_1) { return 0; }

undefined TMapMgr::ApplyUnitMovementClassForTileIfValid(int param_1) { return 0; }

undefined TMapMgr::OrphanRetStub_00515de0() { return 0; }

undefined TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags(int param_1, int param_2) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins27_00516090(int param_1, int param_2) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins18_00516100(int param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins14_00516150(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins12_005161a0(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins10_005161e0(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins09_00516220(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins464_00516260(char param_1, char param_2) { return 0; }

undefined TMapMgr::OrphanCallChain_C3_I41_00517410(char param_1) { return 0; }

undefined TMapMgr::OrphanCallChain_C3_I49_00517480() { return 0; }

undefined TMapMgr::OrphanVtableAssignStub_00517520() { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins55_00517540(short param_1, short param_2) { return 0; }

undefined TMapMgr::OrphanCallChain_C1_I46_00517600(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins04_005176a0(int param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins04_005176c0(int param_1) { return 0; }

undefined TMapMgr::GetMapImprovementTierBucketOffset(short param_1) { return 0; }

undefined TMapMgr::ApplyMapImprovementSelectionState(void * param_1) { return 0; }

undefined TMapMgr::GetMapImprovementSpriteBaseOffset(short param_1, char param_2, char param_3) { return 0; }

undefined TMapMgr::GetMapImprovementTileOffsetFromClass(char param_1) { return 0; }

undefined TMapMgr::GetMapImprovementTileSpriteOffset(short param_1) { return 0; }

undefined TMapMgr::OrphanLeaf_NoCall_Ins08_005178c0() { return 0; }

// FUNCTION: IMPERIALISM 0x00512b50
void TMapMgr::ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
                                                    char wrapHorizontally) {
  unsigned int row = static_cast<unsigned int>(static_cast<int>(tileIndex) / 0x6c);
  int col = static_cast<int>(tileIndex) % 0x6c;
  unsigned int rowParity = row & 1U;
  short sVar4;
  if (rowParity == 0) {
    sVar4 = static_cast<short>(tileIndex + -0x6d);
    neighborTiles[2] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[0] = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[3] = static_cast<short>(tileIndex + 0x6b);
    neighborTiles[1] = static_cast<short>(tileIndex + 1);
    neighborTiles[4] = static_cast<short>(tileIndex + -1);
  } else {
    sVar4 = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[2] = static_cast<short>(tileIndex + 0x6d);
    neighborTiles[0] = static_cast<short>(tileIndex + -0x6b);
    neighborTiles[3] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[1] = static_cast<short>(tileIndex + 1);
    neighborTiles[4] = static_cast<short>(tileIndex + -1);
  }
  neighborTiles[5] = sVar4;
  if (col < 0x6b) {
    if (col == 0) {
      if (wrapHorizontally == '\0') {
        neighborTiles[4] = static_cast<short>(tileIndex + 0x6b);
        if (rowParity == 0) {
          neighborTiles[5] = static_cast<short>(tileIndex + -1);
          neighborTiles[3] = static_cast<short>(tileIndex + 0xd7);
        }
      } else {
        neighborTiles[4] = -1;
        neighborTiles[3] = -1;
        neighborTiles[5] = -1;
      }
    }
  } else if (wrapHorizontally == '\0') {
    neighborTiles[1] = static_cast<short>(tileIndex + -0x6b);
    if (rowParity != 0) {
      neighborTiles[2] = static_cast<short>(tileIndex + 1);
      neighborTiles[0] = static_cast<short>(tileIndex + -0xd7);
    }
  } else {
    neighborTiles[1] = -1;
    neighborTiles[0] = -1;
    neighborTiles[2] = -1;
  }
  if (0x3a < static_cast<int>(row)) {
    neighborTiles[2] = -1;
    neighborTiles[3] = -1;
    return;
  }
  if (row == 0) {
    neighborTiles[0] = -1;
    neighborTiles[5] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x00512cc0
short TMapMgr::GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction) {
  int tile = static_cast<int>(tileIndex);
  int row = tile / 0x6c;
  int col = tile % 0x6c;
  int rowParity = row & 1;
  int scaledCol = rowParity + col * 2;

  int dir = static_cast<int>(direction);
  if (dir < 0) {
    dir += 6;
  } else if (dir > 5) {
    dir -= 6;
  }

  scaledCol += static_cast<int>(g_Build_Hex_Area_LookupTable_00696E70[dir]);

  if (static_cast<short>(direction) < 0) {
    dir = static_cast<int>(static_cast<short>(direction)) + 6;
  } else if (static_cast<short>(direction) > 5) {
    dir = static_cast<int>(static_cast<short>(direction)) - 6;
  }

  short wrappedRow = static_cast<short>(row);
  wrappedRow = static_cast<short>(wrappedRow + g_Build_Hex_Area_LookupTable_00696E80[dir]);

  if (scaledCol > 0xd7) {
    scaledCol -= 0xd9;
  } else if (scaledCol < 0) {
    scaledCol += 0xd8;
  }

  if (wrappedRow < 0) {
    wrappedRow = 0;
  } else if (wrappedRow > 0x3b) {
    wrappedRow = 0x3b;
  }

  int halfCol = scaledCol;
  int halfColSign = halfCol >> 0x1f;
  halfCol = (halfCol - halfColSign) >> 1;
  int result = halfCol + static_cast<int>(wrappedRow) * 0x6c;
  if (result < 0 || result >= 0x1950) {
    return -1;
  }
  return static_cast<short>(result);
}

// FUNCTION: IMPERIALISM 0x00513200
int TMapMgr::SetTileTransportFlags(short nTileIndex, unsigned short wTileTransportFlags) {
  char* terrainTileBytes =
      *reinterpret_cast<char**>(reinterpret_cast<unsigned char*>(this) + 0xc);
  int tileByteOffset = static_cast<int>(nTileIndex) * 0x24;
  unsigned char* flagByte = reinterpret_cast<unsigned char*>(terrainTileBytes + 0x1c + tileByteOffset);
  if (((*flagByte & 4) != 0) && ((wTileTransportFlags & 4) == 0)) {
    RemovePortZoneByTile(nTileIndex);
  }
  *reinterpret_cast<unsigned short*>(flagByte) = wTileTransportFlags;
  if ((wTileTransportFlags & 4) != 0) {
    EnsurePortZoneForTile(nTileIndex);
  }
  if ((wTileTransportFlags & 3) != 0) {
    *flagByte = static_cast<unsigned char>(*flagByte | 0x20);
  }
  return reinterpret_cast<int>(flagByte);
}

namespace {

const int kGlobalMapTileCount = 0x1950;

short FindReachableRecruitSpawnTileRecursiveImpl(TMapMgr* mapState, short tileIndex,
                                                 short ownerNationTag, char allowActiveFlag2) {
  TTerrainStateRecordView* tile = &mapState->terrainStateTable[tileIndex];
  if (tile->recruitSearchVisited0e != 0) {
    return -1;
  }
  tile->recruitSearchVisited0e = 1;
  if (tile->ownerNationTag04 != ownerNationTag) {
    return -1;
  }

  TUnit* civilianOrder = tile->firstCivilianOrder20;
  bool noMatchingCivilian = civilianOrder == 0;
  if (!noMatchingCivilian) {
    while (civilianOrder->field_18 != ownerNationTag) {
      civilianOrder = civilianOrder->nextOnTile;
      if (civilianOrder == 0) {
        noMatchingCivilian = true;
        break;
      }
    }
  }
  if (noMatchingCivilian) {
    if ((tile->activeFlags1c & 2) == 0) {
      return tileIndex;
    }
    if (allowActiveFlag2 != 0) {
      return tileIndex;
    }
  }

  short neighborTiles[6];
  TMapMgr::ComputeHexNeighborTileIndices(tileIndex, neighborTiles,
                                                 mapState->hexNeighborWrapHorizontally20);
  for (short neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    if (neighborTiles[neighborIndex] == -1) {
      continue;
    }
    short foundTile = FindReachableRecruitSpawnTileRecursiveImpl(
        mapState, neighborTiles[neighborIndex], ownerNationTag, allowActiveFlag2);
    if (foundTile != -1) {
      return foundTile;
    }
  }
  return -1;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00513ff0
void TMapMgr::ApplyRailSectionEndpointDirectionFlags(short sourceTile, short destTile, short ownerNation) {
  (void)ownerNation;
  short dir = GetHexDirectionBetweenTiles(sourceTile, destTile);
  char* pTable2 = reinterpret_cast<char*>(g_Build_Hex_Area_LookupTable_00696E80) + 0x32;
  char* pTable8 = reinterpret_cast<char*>(g_Build_Hex_Area_LookupTable_00696E80) + 0x38;
  terrainStateTable[sourceTile].railFlags17 += pTable2[(dir + 3) * 2];
  terrainStateTable[destTile].railFlags17 += pTable8[((dir + 3) % 6) * 2];
}

// FUNCTION: IMPERIALISM 0x00514c80
short TMapMgr::FindReachableRecruitSpawnTileWithVisitedReset(short startTileIndex,
                                                                     char allowActiveFlag2) {
  signed char ownerNationTag = terrainStateTable[startTileIndex].ownerNationTag04;
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  return FindReachableRecruitSpawnTileRecursiveImpl(this, startTileIndex, ownerNationTag,
                                                    allowActiveFlag2);
}

// FUNCTION: IMPERIALISM 0x00515ec0
void TMapMgr::AssignSharedStringFromIndexedA8EntryNameField(int cityRecordIndex, CString* dest) {
  *dest = *reinterpret_cast<CString*>(reinterpret_cast<char*>(cityScoreTable) +
                                       cityRecordIndex * 0xa8 + 0xa4);
}

// FUNCTION: IMPERIALISM 0x005178f0
short TMapMgr::ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(short terrainType,
                                                                        char wrapBias) {
  char* tileTable = reinterpret_cast<char*>(terrainStateTable);
  char* cityTable = reinterpret_cast<char*>(cityScoreTable);
  unsigned int colSum = 0;
  int rowSum = 0;
  unsigned int tileCount = 0;
  int westCount = 0;
  unsigned int eastCount = 0;

  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    int tileByteOffset = tileIndex * 0x24;
    char terrainTag = tileTable[tileByteOffset + 4];
    if (terrainTag != terrainType) {
      continue;
    }
    char includeTile = 1;
    if (terrainType < 0x17 && g_apTerrainTypeDescriptorTable[terrainType] != 0 &&
        g_apTerrainTypeDescriptorTable[terrainType]->ownerNationSlot != static_cast<short>(-1)) {
      short nationSlot = g_apTerrainTypeDescriptorTable[terrainType]->ownerNationSlot;
      short tileCityLink =
          *reinterpret_cast<short*>(tileTable + tileByteOffset + 0x14);
      char tileCityByte =
          cityTable[0xa3 + static_cast<int>(tileCityLink) * 0xa8];
      short nationTileCityLink = *reinterpret_cast<short*>(
          tileTable + nationSlot * 0x24 + 0x14);
      char nationCityByte =
          cityTable[0xa3 + static_cast<int>(nationTileCityLink) * 0xa8];
      if (tileCityByte != nationCityByte) {
        includeTile = 0;
      }
    }
    if (includeTile == 0) {
      continue;
    }
    int tileCol = tileIndex % 0x6c;
    if (tileCol < 0x19) {
      westCount = westCount + 1;
    }
    if (tileCol > 0x53) {
      eastCount = eastCount + 1;
    }
    colSum = colSum + static_cast<unsigned int>(tileCol);
    rowSum = rowSum + tileIndex / 0x6c;
    tileCount = tileCount + 1;
  }

  char applyWrapBias = 0;
  if (westCount >= 1 && static_cast<int>(eastCount) >= 1) {
    applyWrapBias = 1;
    if (wrapBias == 0) {
      tileCount = 0;
      rowSum = 0;
      colSum = 0;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (tileTable[tileIndex * 0x24 + 4] != terrainType) {
          continue;
        }
        int tileCol = tileIndex % 0x6c;
        if (tileCol < 0x36 && westCount < static_cast<int>(eastCount)) {
          tileCol = 0x6b;
        }
        if (tileCol > 0x36 && static_cast<int>(eastCount) < westCount) {
          tileCol = 0;
        }
        colSum = colSum + static_cast<unsigned int>(tileCol);
        rowSum = rowSum + tileIndex / 0x6c;
        tileCount = tileCount + 1;
      }
    } else if (wrapBias != 0) {
      colSum = colSum + static_cast<unsigned int>(westCount * 0x6c);
    }
  }

  if (tileCount != 0) {
    return static_cast<short>(((static_cast<int>(colSum) / static_cast<int>(tileCount)) % 0x6c) +
                              (rowSum / static_cast<int>(tileCount)) * 0x6c);
  }

  short fallbackTile = -1;
  if (terrainType < 0x17 && g_apTerrainTypeDescriptorTable[terrainType] != 0) {
    TSortedList* ownedRegions = g_apTerrainTypeDescriptorTable[terrainType]->ownedRegionList;
    if (ownedRegions != 0 && ownedRegions->GetCountSlot48() > 0) {
      int lastMatch = -1;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (static_cast<signed char>(tileTable[tileIndex * 0x24 + 4]) == terrainType) {
          lastMatch = tileIndex;
        }
      }
      fallbackTile = static_cast<short>(lastMatch);
    }
  }
  return fallbackTile;
}

static const unsigned int kAddrTerrainFlowTypeRemapTable = 0x0065c632;
static const unsigned int kAddrTerrainFlowDirectionTable = 0x0065c668;

namespace {

short FindSeaTileForPortZoneCreation(short portTileIndex, signed char nationSeed) {
  short seaTileIndex = -1;
  short tileWalkIndex = portTileIndex;
  for (int attempt = 0; attempt < 6; ++attempt) {
    short candidateTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(
        portTileIndex, static_cast<short>(tileWalkIndex % 6));
    ++tileWalkIndex;
    if (candidateTile == -1) {
      continue;
    }
    TTerrainStateRecordView& candidateRecord = g_pGlobalMapState->terrainStateTable[candidateTile];
    if (candidateRecord.pad00[0] != 5) {
      continue;
    }
    char allNeighborsMatchNation = 1;
    for (int neighborDirection = 0; neighborDirection < 6; ++neighborDirection) {
      short neighborTile = g_pGlobalMapState->GetWrappedHexNeighborTileIndexByDirection(
          candidateTile, static_cast<short>(neighborDirection));
      if (neighborTile == -1) {
        continue;
      }
      signed char neighborNation =
          g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      if (neighborNation < 0x17 && neighborNation != nationSeed) {
        allNeighborsMatchNation = 0;
        break;
      }
    }
    if (allNeighborsMatchNation != 0) {
      seaTileIndex = candidateTile;
      break;
    }
  }
  if (seaTileIndex == -1) {
    seaTileIndex = TraceTerrainFlowToNearestSeaTile(portTileIndex);
  }
  return seaTileIndex;
}

void LinkPortZoneToContextIfMissing(TZone* portZone, TZone* contextZone) {
  if (contextZone == 0 || portZone == 0) {
    return;
  }
  int entryIndex = 0;
  int primarySize = portZone->primaryNeighbors.GetSize();
  if (primarySize != 0) {
    for (; entryIndex < primarySize; ++entryIndex) {
      if (portZone->primaryNeighbors.GetAt(entryIndex) == contextZone) {
        return;
      }
    }
  }
  portZone->AppendZonePointerToPrimaryArray(contextZone);
  contextZone->AppendZonePointerToSecondaryArray(portZone);
}

} // namespace

// FUNCTION: IMPERIALISM 0x00517c30
char TMapMgr::AreNationsBorderLinked(int nationA, int nationB) {
  TSortedList* regionList = g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList;
  if (regionList->GetCountSlot48() < 1) {
    return 0;
  }
  int ordinal = 1;
  do {
    int regionId = regionList->GetIntByOrdinalSlot24(ordinal);
    TGlobalMapCityScoreRecord* record = &cityScoreTable[regionId];
    char found = 0;
    int neighborCount = record->adjacentRegionCount08;
    if (neighborCount > 0) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
        if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationB) {
          found = 1;
          break;
        }
      }
    }
    if (found != 0) {
      return 1;
    }
    ++ordinal;
  } while (ordinal <= regionList->GetCountSlot48());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00518470
void TMapMgr::ApplyJoinEmpireMode0GlobalDiplomacyReset(int nationSlot) {
  signed char* tileBase = tileOwnershipTable;
  signed char* tagCursor = tileBase + 4;
  int tileIndex = 0;
  do {
    if (*tagCursor >= 7 && *tagCursor <= 0x16) {
      signed char* ownerByte = tileOwnershipTable + static_cast<short>(tileIndex) * 0x24 + 0x18;
      if (*ownerByte == nationSlot) {
        *ownerByte = -1;
      }
    }
    tagCursor += 0x24;
    ++tileIndex;
  } while (tileIndex < 0x1950);
}

// FUNCTION: IMPERIALISM 0x00518960
void TMapMgr::SetRegionDevelopmentStageByte(short regionId, unsigned char stage) {
  cityScoreTable[regionId].developmentStage = stage;
}

// FUNCTION: IMPERIALISM 0x0055e360
short TMapMgr::StepHexTileIndexByDirectionWithWrapRules(short tileIndex,
                                                                short direction) {
  int col = static_cast<int>(tileIndex) % 0x6c;
  unsigned int row = static_cast<unsigned int>(static_cast<int>(tileIndex) / 0x6c);
  if ((direction == 4) || ((direction > 2) && ((row & 1U) == 0U))) {
    col = col - 1;
    if (static_cast<short>(col) < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return -1;
      }
      col = 0x6b;
    }
  } else if (((direction == 1) || ((direction < 3) && ((row & 1U) != 0U)))) {
    col = col + 1;
    if (col > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return -1;
      }
      col = 0;
    }
  }
  if ((direction == 5) || (direction == 0)) {
    if (static_cast<short>(row) - 1 < 0) {
      return -1;
    }
    row = row - 1U;
  } else if (((direction == 3) || (direction == 2)) &&
             (row = row + 1U, static_cast<short>(row) > 0x3b)) {
    return -1;
  }
  return static_cast<short>(col + static_cast<int>(row) * 0x6c);
}

// FUNCTION: IMPERIALISM 0x0055e550
bool TMapMgr::StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction) {
  if ((direction == 4) || ((direction > 2) && (((*row) & 1) == 0))) {
    int nextCol = *col - 1;
    *col = nextCol;
    if (nextCol < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return false;
      }
      *col = 0x6b;
    }
  } else if ((direction == 1) || ((direction < 3) && (((*row) & 1) != 0))) {
    int nextCol = *col + 1;
    *col = nextCol;
    if (nextCol > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return false;
      }
      *col = 0;
    }
  }
  if ((direction == 5) || (direction == 0)) {
    int nextRow = *row - 1;
    *row = nextRow;
    if (nextRow < 0) {
      return false;
    }
  } else if ((direction == 3) || (direction == 2)) {
    int nextRow = *row + 1;
    *row = nextRow;
    if (nextRow > 0x3b) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00560470
void TMapMgr::AdvanceSpiralSearchStateAndStepHexCoordinates(HexSpiralSearchState* state) {
  int stepInRing = state->stepInRing + 1;
  state->stepInRing = stepInRing;
  if (state->ring <= stepInRing) {
    int direction = state->direction + 1;
    state->stepInRing = 0;
    state->direction = direction;
    if (direction > 5) {
      state->ring = state->ring + 1;
      state->direction = 0;
      TMapMgr::StepHexRowColByDirectionWithWrapRules(&state->row, &state->col, 4);
    }
  }
  TMapMgr::StepHexRowColByDirectionWithWrapRules(&state->row, &state->col, state->direction);
}

short TMapMgr::TileIndexFromRowCol(int row, int col) {
  if ((row < 0) || (row > 0x3b) || (col < 0) || (col > 0x6b)) {
    return -1;
  }
  return static_cast<short>(col + row * 0x6c);
}

// FUNCTION: IMPERIALISM 0x005635e0
void EnsurePortZoneForTile(short nTileIndex) {
  if (g_pGlobalMapState == 0) {
    return;
  }
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  int tileIndex = static_cast<int>(nTileIndex);
  if ((terrainTable[tileIndex].activeFlags1c & 1) == 0) {
    return;
  }
  signed char nationSeed = terrainTable[tileIndex].ownerNationTag04;
  if (TZone::FindPortZoneByTile(nTileIndex) != 0) {
    return;
  }

  TPortZone* portZone = TPortZone::CreateTPortZone();
  if (portZone == 0) {
    return;
  }
  portZone->field48 = static_cast<int>(nTileIndex);
  portZone->SetMapActionContextTargetTileAndRefreshMarkers(static_cast<int>(nationSeed), -1);
  portZone->field0c = tileIndex;
  portZone->GenerateZoneStatusCodeIfUnset();
  portZone->GenerateMapActionContextDisplayNameAndHeadline(0, 0);

  short seaTileIndex = FindSeaTileForPortZoneCreation(nTileIndex, nationSeed);
  TZone* linkedContext = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(seaTileIndex);
  LinkPortZoneToContextIfMissing(portZone, linkedContext);

  SetMapTileStateByteAndNotifyObserver(static_cast<int>(seaTileIndex), 3);
  portZone->field0c = static_cast<int>(seaTileIndex);
  portZone->field20 = portZone->GetActiveNationSlotTile();
}

// FUNCTION: IMPERIALISM 0x00563990
short TraceTerrainFlowToNearestSeaTile(short tileIndex) {
  if (g_pGlobalMapState == 0) {
    return -1;
  }
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  for (int flowVariant = 0; flowVariant < 2; ++flowVariant) {
    short flowType = static_cast<short>(terrainTable[tileIndex].roadFlag);
    if (flowType == 0) {
      return -1;
    }
    if (flowType > 0x1a && flowType < 0x2b) {
      flowType = static_cast<short>(flowType - 0x10);
    }
    if (flowType >= 0xb && flowType <= 0x1a) {
      flowType =
          *reinterpret_cast<const short*>(kAddrTerrainFlowTypeRemapTable + flowType * 2);
    } else if (flowType >= 0x2b && flowType <= 0x3a) {
      return -1;
    }

    short stepDirection = *reinterpret_cast<const short*>(
        kAddrTerrainFlowDirectionTable + (flowVariant + flowType * 2) * 2);
    short walkTile = tileIndex;
    for (int stepCount = 0; stepCount < 100; ++stepCount) {
      walkTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
      TTerrainStateRecordView& walkRecord = terrainTable[walkTile];
      if (walkRecord.pad00[0] == 5) {
        return walkTile;
      }

      short nextFlowType = static_cast<short>(walkRecord.roadFlag);
      if (nextFlowType == 0) {
        break;
      }
      if (nextFlowType > 0x1a && nextFlowType < 0x2b) {
        nextFlowType = static_cast<short>(nextFlowType - 0x10);
      }
      if (nextFlowType >= 0xb && nextFlowType <= 0x1a) {
        nextFlowType =
            *reinterpret_cast<const short*>(kAddrTerrainFlowTypeRemapTable + nextFlowType * 2);
      } else if (nextFlowType >= 0x2b && nextFlowType <= 0x3a) {
        break;
      }

      short preferredDirection = static_cast<short>((static_cast<int>(stepDirection) + 3) % 6);
      const short* directionPair =
          reinterpret_cast<const short*>(kAddrTerrainFlowDirectionTable + nextFlowType * 4);
      if (directionPair[0] == preferredDirection) {
        stepDirection = directionPair[1];
      } else if (directionPair[1] != preferredDirection) {
        break;
      } else {
        stepDirection = directionPair[0];
      }
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00564240
void RemovePortZoneByTile(short nTileIndex) {
  for (TZone* zone = TZone::GetFirstPortZone(); zone != 0; zone = zone->GetNextPortZone()) {
    if (static_cast<short>(zone->field0c) == nTileIndex || zone->field20 == nTileIndex ||
        static_cast<short>(zone->field48) == nTileIndex) {
      zone->Free();
      return;
    }
  }
}

char TMapMgr::CallMetricSlotC4(int regionIndex, int edgeIndex) {
  (void)regionIndex;
  (void)edgeIndex;
  return 0;
}

short TMapMgr::QueryIconStripXSlot110(int iconCode) {
  (void)iconCode;
  return 0;
}

void TMapMgr::NotifyCityRecordSlot12C(int cityRecordIndex) {
  (void)cityRecordIndex;
}

void TMapMgr::LinkRegionToNationSlot134(int regionId, int nationSlot) {
  (void)regionId;
  (void)nationSlot;
}
