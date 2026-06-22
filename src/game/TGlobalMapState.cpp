#include "game/TGlobalMapState.h"

#include "game/TPtrList.h"
#include "game/TMinor.h"
#include "game/TCivilianOrderState.h"
#include "game/TPortZone.h"
#include "game/TOcean.h"
#include "game/TZone.h"
#include "game/diplomacy_globals.h"

void EnsurePortZoneForTile(short nTileIndex);
void RemovePortZoneByTile(short nTileIndex);
short TraceTerrainFlowToNearestSeaTile(short tileIndex);

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

extern "C" {
extern short g_Build_Hex_Area_LookupTable_00696E70[];
extern short g_Build_Hex_Area_LookupTable_00696E80[];
}

// FUNCTION: IMPERIALISM 0x00512b50
void TGlobalMapState::ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
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
short TGlobalMapState::GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction) {
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
int TGlobalMapState::SetTileTransportFlags(short nTileIndex, unsigned short wTileTransportFlags) {
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

short FindReachableRecruitSpawnTileRecursiveImpl(TGlobalMapState* mapState, short tileIndex,
                                                 short ownerNationTag, char allowActiveFlag2) {
  TTerrainStateRecordView* tile = &mapState->terrainStateTable[tileIndex];
  if (tile->recruitSearchVisited0e != 0) {
    return -1;
  }
  tile->recruitSearchVisited0e = 1;
  if (tile->ownerNationTag04 != ownerNationTag) {
    return -1;
  }

  TCivilianOrderState* civilianOrder = tile->firstCivilianOrder20;
  bool noMatchingCivilian = civilianOrder == 0;
  if (!noMatchingCivilian) {
    while (civilianOrder->ownerNationSlot18 != ownerNationTag) {
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
  TGlobalMapState::ComputeHexNeighborTileIndices(tileIndex, neighborTiles,
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

// FUNCTION: IMPERIALISM 0x00513290
void TGlobalMapState::DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
    short regionIndex, int newOwnerNationSlot) {
  (void)regionIndex;
  (void)newOwnerNationSlot;
}

// FUNCTION: IMPERIALISM 0x00514c80
short TGlobalMapState::FindReachableRecruitSpawnTileWithVisitedReset(short startTileIndex,
                                                                     char allowActiveFlag2) {
  signed char ownerNationTag = terrainStateTable[startTileIndex].ownerNationTag04;
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  return FindReachableRecruitSpawnTileRecursiveImpl(this, startTileIndex, ownerNationTag,
                                                    allowActiveFlag2);
}

// FUNCTION: IMPERIALISM 0x00517c30
char TGlobalMapState::AreNationsBorderLinked(int nationA, int nationB) {
  TPtrList* regionList = g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList;
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

// FUNCTION: IMPERIALISM 0x00518960
void TGlobalMapState::SetRegionDevelopmentStageByte(short regionId, unsigned char stage) {
  cityScoreTable[regionId].developmentStage = stage;
}

// FUNCTION: IMPERIALISM 0x0055e360
short TGlobalMapState::StepHexTileIndexByDirectionWithWrapRules(short tileIndex,
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

static const unsigned int kAddrTerrainFlowTypeRemapTable = 0x0065c632;
static const unsigned int kAddrTerrainFlowDirectionTable = 0x0065c668;

namespace {

TZone* ResolveLinkedMapActionContextForSeaTile(short seaTileIndex) {
  TTerrainStateRecordView& terrainRecord = g_pGlobalMapState->terrainStateTable[seaTileIndex];
  signed char terrainClass =
      *reinterpret_cast<signed char*>(reinterpret_cast<char*>(&terrainRecord) + 0x16);
  if (terrainClass == 3 || terrainClass == 0x0e) {
    return TZone::FindPortZoneByTile(seaTileIndex);
  }
  signed char nationCode = terrainRecord.ownerNationTag04;
  if (nationCode < 0x17) {
    return 0;
  }
  return g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(
      static_cast<short>(nationCode));
}

short FindSeaTileForPortZoneCreation(short portTileIndex, signed char nationSeed) {
  short seaTileIndex = -1;
  short tileWalkIndex = portTileIndex;
  for (int attempt = 0; attempt < 6; ++attempt) {
    short candidateTile = TGlobalMapState::StepHexTileIndexByDirectionWithWrapRules(
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
  unsigned int entryIndex = 0;
  if (portZone->portZoneActiveEntryCount30 != 0) {
    for (; entryIndex < static_cast<unsigned int>(portZone->portZoneActiveEntryCount30);
         ++entryIndex) {
      if (reinterpret_cast<TZone*>(portZone->portZoneEntries28[entryIndex]) == contextZone) {
        return;
      }
    }
  }
  portZone->AppendZonePointerToPrimaryArray();
  contextZone->AppendZonePointerToSecondaryArray();
}

} // namespace

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
  TZone* linkedContext = ResolveLinkedMapActionContextForSeaTile(seaTileIndex);
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
      walkTile = TGlobalMapState::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
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
