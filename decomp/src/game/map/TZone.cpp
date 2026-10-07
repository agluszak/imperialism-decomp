#include "game/nation_domain_types.h"
#include "game/map_domain_types.h"
#include "game/ui_tags_common.h"

#include "game/map/TZone.h"
#include "game/core/runtime_prng_seed.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_screens_globals.h"

#include <cstdlib>
#include <new>

#include "game/military/mapped_flavor_text.h"
#include "game/mfc.h"
#include "game/navy/TAdmiral.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/gfx/TResourceMgr.h"
#include "game/navy/TOcean.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ui_screens/TPortZone.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"

namespace {

static int SignedRemainderByFour(int value) {
  return value % 4;
}

static short TileIndexFromRowCol(int row, int col) {
  if (row < 0 || row >= kStrategicMapRows || col < 0 || col >= kStrategicMapColumns) {
    return -1;
  }
  return static_cast<short>(col + row * kStrategicMapColumns);
}

enum { kFirstMapRegionNationTag = 0x17 };

} // namespace

IMPLEMENT_DYNCREATE(TZone, TObject)

// FUNCTION: IMPERIALISM 0x0055e700
TZone::TZone() : displayName(), primaryNeighbors(), secondaryNeighbors() {
  seedNationId = -1;
  contextOrdinal = static_cast<short>(g_nMapActionContextCount);
  ++g_nMapActionContextCount;
  tileOrTerrainId = -1;
  nationKeyMask = 0;
  prevZone = g_pMapActionContextListHead;
  nextZone = 0;
  distanceLevel = 0;
  statusCode = -1;
  activeTileIndex = -1;
  g_pMapActionContextListHead = this;
  if (prevZone != 0) {
    prevZone->nextZone = this;
  }
  if (g_pMapActionContextDistanceCache != 0) {
    delete[] static_cast<char*>(g_pMapActionContextDistanceCache);
    g_pMapActionContextDistanceCache = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0055e820
bool TZone::IsSeaZone() {
  return true;
}

// FUNCTION: IMPERIALISM 0x0055e840
bool TZone::IsPortZone() {
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e860
bool TZone::IsProvincial() {
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e880
bool TZone::IsFriendlyWith(NationSlot nationSlot) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e8a0
bool TZone::IsEnemyOf(NationSlot nationSlot) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0055e8c0
bool TZone::CanBeTargetOf(TTaskForce* force) {
  return distanceLevel > 0;
}

// FUNCTION: IMPERIALISM 0x0055e8e0
TZone** TZonePrimaryNeighborStretch::Add(TZone* zone) {
  TZone** existing = FindEntry(zone);
  if (existing != 0) {
    return existing;
  }
  return stretch<TZone*>::Add(zone);
}

// FUNCTION: IMPERIALISM 0x0055e9c0
Province** TZoneSecondaryNeighborStretch::Add(Province* entry) {
  Province** existing = FindEntry(entry);
  if (existing != 0) {
    return existing;
  }
  return stretch<Province*>::Add(entry);
}

// FUNCTION: IMPERIALISM 0x0055ec60
void TZone::Free() {
  Vanish();
  delete this;
}

// FUNCTION: IMPERIALISM 0x0055ecd0
void TZone::Vanish() {
  if (g_pMapActionContextListHead == this) {
    g_pMapActionContextListHead = prevZone;
  }
  if (prevZone != 0) {
    prevZone->nextZone = nextZone;
  }
  if (nextZone != 0) {
    nextZone->prevZone = prevZone;
  }
  nextZone = 0;
  prevZone = 0;
}

// FUNCTION: IMPERIALISM 0x0055ed20
void TZone::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadSharedString(&displayName, 0x20);
  stream->ReadBytes(&statusCode, 2);
  stream->ReadBytes(&tileOrTerrainId, 4);
  stream->ReadBytes(&seedNationId, 2);
  stream->ReadBytes(&activeTileIndex, 2);
  if (g_nSaveFormatVersion < 0x12) {
    contextOrdinal = static_cast<short>(g_nMapActionContextCount);
    ++g_nMapActionContextCount;
  } else {
    stream->ReadBytes(&contextOrdinal, 2);
  }
  nationKeyMask = 0;
  distanceLevel = 0;

  if (primaryNeighbors.Data() != 0) {
    free(primaryNeighbors.Detach());
  }
  if (secondaryNeighbors.Data() != 0) {
    free(secondaryNeighbors.Detach());
  }

  if (g_nSaveFormatVersion < 0xd) {
    {
      short neighborCount;
      stream->ReadBytes(&neighborCount, 2);
      for (short neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        TZone* entry;
        stream->ReadBytes(&entry, 4);
        primaryNeighbors[static_cast<unsigned int>(neighborIndex)] = entry;
      }
    }

    {
      short neighborCount;
      stream->ReadBytes(&neighborCount, 2);
      for (short neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        Province* entry;
        stream->ReadBytes(&entry, 4);
        secondaryNeighbors[static_cast<unsigned int>(neighborIndex)] = entry;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0055eff0
void TZone::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteSharedString(&displayName);
  stream->WriteBytes(&statusCode, 2);
  stream->WriteBytes(&tileOrTerrainId, 4);
  stream->WriteBytes(&seedNationId, 2);
  stream->WriteBytes(&activeTileIndex, 2);
  stream->WriteBytes(&contextOrdinal, 2);
}

// FUNCTION: IMPERIALISM 0x0055f070
void TZone::AssignZoneDisplayNameToOutputRef(CString* outputRef) {
  *outputRef = displayName;
}

// FUNCTION: IMPERIALISM 0x0055f090
void TZone::AssignZoneDisplayNameAliasToOutputRef(CString* outputRef) {
  *outputRef = displayName;
}

// FUNCTION: IMPERIALISM 0x0055f0b0
short TZone::GetContextOrdinalOrInvalid() {
  if (this == 0) {
    return -1;
  }
  return contextOrdinal;
}

// FUNCTION: IMPERIALISM 0x0055f0d0
TZone* GetLastMapActionContext() {
  TZone* zone = g_pMapActionContextListHead;
  while (zone != 0 && zone->prevZone != 0) {
    zone = zone->prevZone;
  }
  return zone;
}

// FUNCTION: IMPERIALISM 0x0055f100
TZone* FindMapActionContextByNodeId(short nodeId) {
  if (nodeId == -1) {
    return 0;
  }
  TZone* node;
  for (node = g_pMapActionContextListHead; node != 0; node = node->prevZone) {
    short ordinal = (node != 0) ? node->contextOrdinal : -1;
    if (ordinal == nodeId) {
      break;
    }
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x0055f140
int TZone::GetStrategicValue() {
  if (IsPortZone()) {
    AssertValid();
    int ownerTag =
        g_pGlobalMapState->terrainStateTable[static_cast<TPortZone*>(this)->portTileIndex]
            .ownerNationTag;
    if (g_pSimMgr->ReallyInTheGame(ownerTag)) {
      return g_pGlobalMapState
          ->cityScoreTable[g_apTerrainTypeDescriptorTable[ownerTag]->GetCapitolProvince()]
          .cityScoreValue;
    }
  } else if (secondaryNeighbors.Count() != 0) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < static_cast<unsigned int>(secondaryNeighbors.Count()); ++i) {
      sum +=
          g_pGlobalMapState->cityScoreTable[static_cast<short>(secondaryNeighbors[i]->GetIndex())]
              .cityScoreValue;
    }
    return sum / secondaryNeighbors.Count();
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055f300
void TZone::AddNeighbor(TZone* zone) {
  primaryNeighbors.Add(zone);
}

// FUNCTION: IMPERIALISM 0x0055f320
bool TZone::HasNeighbor(TZone* zone) {
  return primaryNeighbors.FindEntry(zone) != 0;
}

// FUNCTION: IMPERIALISM 0x0055f3a0
void TZone::AppendUniqueSecondaryNeighbor(Province* province) {
  secondaryNeighbors.Add(province);
}

// FUNCTION: IMPERIALISM 0x0055f3c0
bool TZone::HasNeighbor(Province* province) {
  return secondaryNeighbors.FindEntry(province) != 0;
}

// FUNCTION: IMPERIALISM 0x0055f440
bool TZone::ContainsProvince(short cityIndex) {
  unsigned int entryCount = secondaryNeighbors.Count();
  const Province* target = &g_pGlobalMapState->cityScoreTable[cityIndex];
  Province* const* entrySlot = 0;
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    if (secondaryNeighbors.Data()[entryIndex] == target) {
      entrySlot = secondaryNeighbors.Data() + entryIndex;
      break;
    }
  }
  return entrySlot != 0;
}

// FUNCTION: IMPERIALISM 0x0055f4d0
bool TZone::IsAdjacentToCountry(short nationTag) {
  unsigned int entryCount = secondaryNeighbors.Count();
  if (entryCount == 0) {
    return false;
  }
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    Province* const* entrySlot =
        (entryIndex < entryCount) ? secondaryNeighbors.Data() + entryIndex : 0;
    short entryNationTag = (*entrySlot)->ownerNationCode;
    if (entryNationTag == nationTag) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x0055f540
int TZone::IsVisibleToCountry(short key) {
  unsigned char keyBit = 1 << key;
  if ((keyBit & nationKeyMask) != 0) {
    return 1;
  }
  unsigned int entryCount = secondaryNeighbors.Count();
  for (unsigned int entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
    Province* const* entrySlot =
        (entryIndex < entryCount) ? secondaryNeighbors.Data() + entryIndex : 0;
    short entryKey = (*entrySlot)->ownerNationCode;
    if (entryKey == key) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x0055f5c0
void TZone::GenerateZoneStatusCodeIfUnset() {
  if (statusCode != -1) {
    return; // status code already assigned
  }
  short category;
  if (IsPortZone()) {
    category = 5; // port zones are always the highest status band
  } else {
    category = static_cast<short>(primaryNeighbors.Count());
    if (category == 2) {
      TZone* neighbor0 = primaryNeighbors[0];
      unsigned int neighborCount = neighbor0->primaryNeighbors.Count();
      if (neighborCount != 0) {
        TZone** scan = neighbor0->primaryNeighbors.Data();
        TZone* target = primaryNeighbors[1];
        unsigned int i = 0;
        do {
          if (*scan == target) {
            category = 1;
            break;
          }
          ++i;
          ++scan;
        } while (i < neighborCount);
      }
    }
    if (category > 5) {
      category = 4;
    } else if (category > 3) {
      category = 3;
    }
    if (secondaryNeighbors.Count() == 0) {
      category = 4;
    } else if (category == 4) {
      category = 3;
    }
  }
  g_zoneStatusCodePrngSeed = g_zoneStatusCodePrngSeed * 0x15a4e35 + 1;
  statusCode = static_cast<short>(((g_zoneStatusCodePrngSeed >> 0xc) & 3) + category * 4);
}

// FUNCTION: IMPERIALISM 0x0055f780
void TZone::NameThyself(unsigned char* usedCityFlags, const char* overrideName) {
  if (overrideName != 0) {
    CString providedName(overrideName);
    displayName = providedName;
  } else {
    int chosenCity = -1;
    if (usedCityFlags != 0 && secondaryNeighbors.Count() != 0) {
      g_zoneStatusCodePrngSeed = g_zoneStatusCodePrngSeed * 0x15a4e35 + 1;
      unsigned int pick = (g_zoneStatusCodePrngSeed >> 0xc & 0x7fff) %
                          static_cast<unsigned int>(secondaryNeighbors.Count());
      Province* cityRecord = secondaryNeighbors[pick];
      short tile = cityRecord->linkedTileIndices[0];
      chosenCity = g_pGlobalMapState->terrainStateTable[tile].cityRecordIndex;
      if (usedCityFlags[chosenCity] != 0) {
        chosenCity = -1;
      } else {
        usedCityFlags[chosenCity] = 1;
      }
    }
    if (chosenCity != -1) {
      g_pGlobalMapState->AssignCityRecordDisplayName(chosenCity, &displayName);
    } else {
      if (g_pSimMgr->useLocalizedNameTables != 0) {
        if (g_mapActionContextDisplayNameCacheId == -1) {
          unsigned int randomValue = g_zoneStatusCodePrngSeed * 0x15a4e35U + 1;
          int nameIndex = (randomValue >> 0xc) & 0x7fff;
          g_mapActionContextDisplayNameCacheId = nameIndex % 37;
          unsigned int nextRandomValue = randomValue * 0x15a4e35U + 1;
          g_zoneStatusCodePrngSeed = nextRandomValue;
          int strides[4] = {1, 7, 0xb, 0x17};
          int strideSelector = (nextRandomValue >> 0xc) & 0x7fff;
          int strideIndex = SignedRemainderByFour(strideSelector);
          g_mapActionContextDisplayNameCacheStep = strides[strideIndex];
        }
        CString resourceName;
        g_pSimMgr->GetString(0x275b, static_cast<short>(g_mapActionContextDisplayNameCacheId),
                             &resourceName);
        displayName = resourceName;
        g_mapActionContextDisplayNameCacheId += g_mapActionContextDisplayNameCacheStep;
        if (g_mapActionContextDisplayNameCacheId >= 0x25) {
          g_mapActionContextDisplayNameCacheId -= 0x25;
        }
      } else {
        GenerateFlavorTextForNation(&displayName);
      }
    }
  }
  // Build the headline by expanding the status-code-selected template with the display name.
  CString headlineTemplate;
  g_pSimMgr->GetString(0x275a, statusCode, &headlineTemplate);
  CString expanded;
  scanBracketExpressions(g_pSimMgr, &expanded, headlineTemplate, static_cast<LPCSTR>(displayName));
  displayName = expanded;
}

// FUNCTION: IMPERIALISM 0x0055fb60
void TZone::SetIngotTile(short nationSeedId, int tileIndex) {
  seedNationId = nationSeedId;
  unsigned short resolvedTile = tileIndex;
  if (resolvedTile == 0xffff) {
    resolvedTile =
        static_cast<unsigned short>(g_pGlobalMapState->GetNationCenterTile(nationSeedId, false));
  }
  tileOrTerrainId = static_cast<short>(resolvedTile);
  activeTileIndex = static_cast<short>(tileOrTerrainId);
  if (IsPortZone()) {
    g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
        activeTileIndex, -kMapTileActionStatePortZoneMarkerFrame);
    return;
  }
  g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
      activeTileIndex, -kMapTileActionStateZoneCenterMarkerFrame);
  activeTileIndex = TMapMgr::StepTile(activeTileIndex, kStrategicHexDirectionNorthWest);
  g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
      activeTileIndex, -kMapTileActionStateZoneNorthWestMarkerFrame);
  activeTileIndex = TMapMgr::StepTile(activeTileIndex, kStrategicHexDirectionNorthEast);
  g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
      activeTileIndex, -kMapTileActionStateZoneNorthEastMarkerFrame);
}

// FUNCTION: IMPERIALISM 0x0055fc40
void TZone::OccupyBy(int nation) {
  if ((nationKeyMask & (1U << (nation & 0x1f))) == 0) {
    nationKeyMask = static_cast<unsigned short>(nationKeyMask | (1U << (nation & 0x1f)));
    short player = g_pSimMgr->GetPlayerCountry();

    bool playerSeesZone = (nationKeyMask & (1U << (player & 0x1f))) != 0;
    Province** provinces = secondaryNeighbors.Data();
    unsigned int provinceCount = secondaryNeighbors.GetSize();
    for (unsigned int i = 0; !playerSeesZone && i < provinceCount; ++i) {
      if (provinces[i]->ownerNationCode == static_cast<char>(player)) {
        playerSeesZone = true;
      }
    }

    if (playerSeesZone) {
      if (player == static_cast<short>(nation)) {
        ShowFocusIngot(1);
        for (int other = player + 1; other < player + 7; ++other) {
          if ((nationKeyMask & (1U << ((other % 7) & 0x1f))) != 0) {
            short tile = PickIngotTile();
            g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
                tile, other % 7 + kMapTileActionStateNationOrderFirst);
            g_pGlobalMapState->terrainStateTable[tile].tileActionOrdinal = -1;
          }
        }
      } else {
        short tile = PickIngotTile();
        g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
            tile, kMapTileActionStateNationOrderFirst);
        g_pGlobalMapState->terrainStateTable[tile].tileActionOrdinal = -1;
      }
    }
  }

  short player = g_pSimMgr->GetPlayerCountry();
  if (player == -1) {
    player = g_pSimMgr->GetPlayerCountry();
  }

  if ((nationKeyMask & (1U << (player & 0x1f))) != 0) {
    for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
      if (ship->location == this && ship->nation == player && ship->taskForce == 0) {
        ShowFocusIngot(1);
        return;
      }
    }
  }
  ShowFocusIngot(0);
}

// FUNCTION: IMPERIALISM 0x0055fe60
short TZone::PickPennantIngotTile() {
  short stepSign = 1;
  short tileIndex = tileOrTerrainId + 0xd8;
  short stepMagnitude = 1;
  for (;;) {
    TTerrainStateRecord& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tileRecord.tileActionState == kMapTileActionStateNone) {
      short nationId = tileRecord.ownerNationTag;
      TZone* contextZone = 0;
      if (nationId >= kNationSlotCount && g_pActiveMapOrderContext != 0) {
        contextZone = &g_pActiveMapOrderContext->contextArray[nationId - 0x17];
      }
      if (contextZone != 0) {
        return tileIndex;
      }
    }
    tileIndex += stepSign * stepMagnitude;
    ++stepMagnitude;
    stepSign = static_cast<short>(-stepSign);
  }
}

// FUNCTION: IMPERIALISM 0x0055fef0
short TZone::PickIngotTile() {
  short tileIndex = tileOrTerrainId;
  short stepSign = 1;
  short stepMagnitude = 1;
  for (;;) {
    TTerrainStateRecord& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tileRecord.tileActionState == kMapTileActionStateNone) {
      short nationId = tileRecord.ownerNationTag;
      TZone* contextZone = 0;
      if (nationId >= kNationSlotCount && g_pActiveMapOrderContext != 0) {
        contextZone = &g_pActiveMapOrderContext->contextArray[nationId - 0x17];
      }
      if (contextZone != 0) {
        return tileIndex;
      }
    }
    tileIndex += stepMagnitude * stepSign;
    ++stepMagnitude;
    stepSign = static_cast<short>(-stepSign);
  }
}

// FUNCTION: IMPERIALISM 0x0055ff70
int TZone::ScoreCoastalTile(short tileIndex, TZone* contextZone, Province* contextProvince) {
  TTerrainStateRecord& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
  if (tileRecord.GetTerrainKind() != kStrategicTerrainWater) {
    return 0;
  }
  if (tileRecord.tileActionState != kMapTileActionStateNone) {
    return 0;
  }
  TZone* zoneForTile = 0;
  if (g_pActiveMapOrderContext != 0) {
    zoneForTile = g_pActiveMapOrderContext->GetZoneAt(tileIndex);
  }
  if (zoneForTile != contextZone) {
    return 0x3e8;
  }

  int score = 0x1388;
  for (int neighborDir = 0; neighborDir < 6; ++neighborDir) {
    short neighborTile = TMapMgr::StepTile(tileIndex, static_cast<short>(neighborDir));
    if (neighborTile != -1) {
      TTerrainStateRecord& neighborRecord = g_pGlobalMapState->terrainStateTable[neighborTile];
      if (neighborRecord.GetTerrainKind() == kStrategicTerrainWater) {
        signed char neighborSubtype = neighborRecord.tileActionState;
        if (neighborSubtype == kMapTileActionStateAnchor ||
            neighborSubtype == kMapTileActionStateDockedFleet) {
          TZone* portZone = TZone::FindPortZoneByTile(neighborTile);
          if (portZone != contextZone) {
            --score;
          }
        } else {
          short cityStateLink = neighborRecord.cityRecordIndex;
          Province* province = 0;
          if (cityStateLink != -1) {
            province = &g_pGlobalMapState->cityScoreTable[cityStateLink];
          }
          if (province == contextProvince) {
            score += 0x64;
          } else {
            score -= 0xa;
          }
        }
      }
    }
  }

  return score;
}

// FUNCTION: IMPERIALISM 0x00560150
short TZone::PickInvasionIngotTile(Province* contextProvince) {
  short tileCandidate = 0;

  for (;;) {
    TTerrainStateRecord& tileRecord = g_pGlobalMapState->terrainStateTable[tileCandidate];
    bool isWater = tileRecord.GetTerrainKind() == kStrategicTerrainWater;
    if (isWater) {
      TZone* zoneForTile;
      short tileActionState = static_cast<signed char>(tileRecord.tileActionState);
      if (tileActionState == kMapTileActionStateAnchor ||
          tileActionState == kMapTileActionStateDockedFleet) {
        zoneForTile = TZone::FindPortZoneByTile(tileCandidate);
      } else {
        short nationCode = tileRecord.ownerNationTag;
        if (nationCode < kFirstMapRegionNationTag) {
          zoneForTile = 0;
        } else {
          zoneForTile =
              &g_pActiveMapOrderContext->contextArray[nationCode - kFirstMapRegionNationTag];
        }
      }
      if (zoneForTile == this) {
        int neighborDir;
        for (neighborDir = 0; neighborDir < 6; ++neighborDir) {
          short neighborTile = TMapMgr::StepTile(tileCandidate, static_cast<short>(neighborDir));
          if (neighborTile != -1) {
            TTerrainStateRecord& neighborRecord =
                g_pGlobalMapState->terrainStateTable[neighborTile];
            int neighborIsWater = neighborRecord.GetTerrainKind() == kStrategicTerrainWater;
            if (!neighborIsWater) {
              short cityStateLink = neighborRecord.cityRecordIndex;
              Province* province = 0;
              if (cityStateLink != -1) {
                province = &g_pGlobalMapState->cityScoreTable[cityStateLink];
              }
              if (province == contextProvince) {
                break;
              }
            }
          }
        }
        if (neighborDir < 6) {
          break;
        }
      }
    }
    ++tileCandidate;
    if (tileCandidate >= kStrategicTileCount) {
      break;
    }
  }

  if (tileCandidate >= kStrategicTileCount) {
    tileCandidate = static_cast<short>(tileOrTerrainId + 0x6c);
  }

  short bestTile = tileCandidate;
  int bestTileIndex = bestTile;
  int bestScore = ScoreCoastalTile(bestTileIndex, this, contextProvince);

  HexSpiralSearchState spiral;
  spiral.row = bestTileIndex / kStrategicMapColumns;
  spiral.col = bestTileIndex % kStrategicMapColumns;
  spiral.ring = 0;
  spiral.direction = 5;
  spiral.stepInRing = 1;
  TMapMgr::StepSpiral(&spiral);

  while (spiral.ring < 0xc) {
    short spiralTile = TileIndexFromRowCol(spiral.row, spiral.col);

    bool tileInBounds;
    if ((spiralTile < 0) || (spiralTile) > 0x194f) {
      tileInBounds = false;
    } else {
      tileInBounds = true;
    }

    if (tileInBounds) {
      int spiralTileIndex = TileIndexFromRowCol(spiral.row, spiral.col);
      int candidateScore = ScoreCoastalTile(spiralTileIndex, this, contextProvince);
      if (bestScore < candidateScore) {
        bestScore = candidateScore;
        tileCandidate = TileIndexFromRowCol(spiral.row, spiral.col);
      }
    }

    bestTile = tileCandidate;
    ++spiral.stepInRing;
    if (spiral.ring <= spiral.stepInRing) {
      spiral.stepInRing = 0;
      ++spiral.direction;
      if (spiral.direction > 5) {
        ++spiral.ring;
        spiral.direction = 0;
        TMapMgr::StepHexRowColByDirectionWithWrapRules(&spiral.row, &spiral.col,
                                                       kStrategicHexDirectionWest);
      }
    }
    TMapMgr::StepHexRowColByDirectionWithWrapRules(&spiral.row, &spiral.col, spiral.direction);
  }

  return bestTile;
}

// FUNCTION: IMPERIALISM 0x005604e0
void TZone::ReconsiderFocusIngot() {
  short activeNation = g_pSimMgr->GetPlayerCountry();
  if (activeNation == -1) {
    activeNation = g_pSimMgr->GetPlayerCountry();
  }

  if ((nationKeyMask & (1U << (static_cast<unsigned char>(activeNation) & 0x1f))) != 0) {
    for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
      if (ship->location == this && ship->nation == activeNation && ship->taskForce == 0) {
        ShowFocusIngot(1);
        return;
      }
    }
  }
  ShowFocusIngot(0);
}

// FUNCTION: IMPERIALISM 0x00560580
void TZone::ShowFocusIngot(unsigned char flag) {
  unsigned char tileStateByte =
      g_pGlobalMapState->terrainStateTable[activeTileIndex].tileActionState;
  if (((flag != static_cast<unsigned char>(static_cast<signed char>(tileStateByte) >= 0 ? 1 : 0)) &&
       (g_pViewMgr != 0)) &&
      (g_pViewMgr->mapUberPicture != 0)) {
    char sign = flag ? 1 : -1;
    if (IsPortZone()) {
      g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
          activeTileIndex, static_cast<int>(sign) * kMapTileActionStatePortZoneMarkerFrame);
      g_pViewMgr->mapUberPicture->InvalidateTile(activeTileIndex);
      return;
    }
    int magnitude = sign;
    short centerTile = activeTileIndex;
    g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
        centerTile, magnitude * kMapTileActionStateZoneCenterMarkerFrame);
    g_pViewMgr->mapUberPicture->InvalidateTile(centerTile);
    short northWestTile = TMapMgr::StepTile(centerTile, kStrategicHexDirectionNorthWest);
    g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
        northWestTile, magnitude * kMapTileActionStateZoneNorthWestMarkerFrame);
    g_pViewMgr->mapUberPicture->InvalidateTile(northWestTile);
    short northEastTile = TMapMgr::StepTile(centerTile, kStrategicHexDirectionNorthEast);
    g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(
        northEastTile, magnitude * kMapTileActionStateZoneNorthEastMarkerFrame);
    g_pViewMgr->mapUberPicture->InvalidateTile(northEastTile);
  }
}

// FUNCTION: IMPERIALISM 0x005606f0
void TZone::GetNavalAuthority(CString* out, short nation) {
  TShip* selected = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this && ship->nation == nation) {
      selected = selected->Finest(ship, false);
    }
  }

  if (selected == 0) {
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(out, 0x2762, 0x10);
    return;
  }

  if (selected->admiral != 0) {
    CString admiralName;
    CString shipName;
    CString reportTemplate;
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0xe);
    admiralName = s_szAdmiralPrefix + selected->admiral->displayName;
    shipName = selected->name;
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(admiralName), static_cast<LPCSTR>(shipName));
  } else {
    CString shipName;
    CString reportTemplate;
    shipName = selected->name;
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&reportTemplate, 0x2762, 0xf);
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(reportTemplate),
                           static_cast<LPCSTR>(shipName));
  }
}

// FUNCTION: IMPERIALISM 0x00560970
TAdmiral* TZone::GetSeniorOfficerOf(int nation) {
  TShip* selected = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this && ship->nation == nation) {
      selected = selected->Finest(ship, false);
    }
  }
  return selected != 0 ? selected->admiral : 0;
}

// FUNCTION: IMPERIALISM 0x005609e0
TTaskForce* TZone::AssembleTaskForce(short nation) {
  int resolvedNation = nation;
  if (resolvedNation == -1) {
    resolvedNation = g_pSimMgr->GetPlayerCountry();
  }
  unsigned char nationBit = 1 << static_cast<short>(resolvedNation);
  if ((nationKeyMask & nationBit) != 0) {
    for (TShip* ship = TShip::GetFirst(); ship != NULL; ship = ship->next) {
      if (ship->location == this && ship->nation == resolvedNation && ship->taskForce == 0) {
        TTaskForce* taskForce = new TTaskForce(this, nation);
        taskForce->ITaskForce();
        taskForce->MaxOut(0);
        taskForce->DemocraticallyDetermineAggressionLevel();
        return taskForce;
      }
    }
  }
  return NULL;
}

// FUNCTION: IMPERIALISM 0x00560b00
bool TZone::HasFreeShipsOfPlayer(int nation, bool skipField34Check) {
  if (nation == -1) {
    nation = g_pSimMgr->GetPlayerCountry();
  }
  unsigned char nationBit = 1 << nation;
  if ((nationKeyMask & nationBit) == 0) {
    return false;
  }
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this && ship->nation == nation) {
      if (!skipField34Check) {
        bool hasField34 = (ship->selection != 0);
        if (hasField34) {
          continue;
        }
      }
      if (ship->taskForce == 0) {
        return true;
      }
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00560ba0
void TZone::LightUp(int remainingDepth, bool markAdjacentCities) {
  short depth = remainingDepth;
  if (distanceLevel > depth) {
    return;
  }

  distanceLevel = static_cast<short>(depth + 1);
  if (depth > 0) {
    for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
      TZone* neighbor = primaryNeighbors.GetAt(i);
      if (markAdjacentCities || neighbor->IsSeaZone()) {
        neighbor->LightUp(depth - 1, false);
      }
    }

    if (markAdjacentCities) {
      for (int i = secondaryNeighbors.Count() - 1; i >= 0; --i) {
        Province* city = secondaryNeighbors.Data()[i];
        city->navyOrderReachable = 1;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00560e20
void ResetZoneActivity() {
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prevZone) {
    zone->distanceLevel = 0;
  }
  for (int cityIndex = 0; cityIndex < kProvinceCount; ++cityIndex) {
    g_pGlobalMapState->cityScoreTable[cityIndex].navyOrderReachable = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00560e70
TZone* TZone::GetSafestNearbyZoneFor(short nationSlot) const {
  TZone* bestNeighbor = 0;
  int bestWarCount = -1;
  for (int neighborIndex = 0; neighborIndex < primaryNeighbors.GetSize(); ++neighborIndex) {
    TZone* neighbor = primaryNeighbors.GetAt(neighborIndex);
    if (!neighbor->IsPortZone() || neighbor->IsFriendlyWith(nationSlot)) {
      int warCount = 0;
      for (int otherNation = 0; otherNation < kMajorNationCount; ++otherNation) {
        if (g_apTerrainTypeDescriptorTable[otherNation] != 0 &&
            (neighbor->nationKeyMask & (1 << otherNation)) != 0 &&
            g_pDiplomacyTurnStateManager->AreAtWar(nationSlot, otherNation)) {
          ++warCount;
        }
      }
      if (bestWarCount < warCount) {
        bestWarCount = warCount;
        bestNeighbor = neighbor;
      }
    }
  }
  return bestNeighbor;
}

// FUNCTION: IMPERIALISM 0x00560f80
void TZone::LightDistanceRecursive(short level) {
  if (level == -1) {
    for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prevZone) {
      node->distanceLevel = 0x29a;
    }
    level = 0;
  }
  if (level < distanceLevel) {
    distanceLevel = level;
    for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
      TZone* neighbor = primaryNeighbors[static_cast<unsigned int>(i)];
      neighbor->LightDistanceRecursive(static_cast<short>(level + 1));
    }
  }
}

// FUNCTION: IMPERIALISM 0x005610b0
short TZone::GetDistanceTo(TZone* other) {
  if (other == this) {
    return 0;
  }

  if (g_pMapActionContextDistanceCache == 0 ||
      g_nMapActionContextCount != g_nMapActionContextDistanceCacheSizedFor) {
    g_nMapActionContextDistanceCacheSizedFor = g_nMapActionContextCount;
    int cellCount = g_nMapActionContextCount * g_nMapActionContextCount;
    char* newCache = new char[cellCount];
    for (int i = 0; i < cellCount; ++i) {
      newCache[i] = -1;
    }
    g_pMapActionContextDistanceCache = newCache;
  }

  short thisOrd = this != 0 ? contextOrdinal : -1;
  short otherOrd = other != 0 ? other->contextOrdinal : -1;
  char* cache = static_cast<char*>(g_pMapActionContextDistanceCache);
  signed char cachedDistance = cache[thisOrd * g_nMapActionContextCount + otherOrd];

  if (cachedDistance < 0) {
    for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prevZone) {
      node->distanceLevel = 0x29a;
    }

    if (distanceLevel > 0) {
      distanceLevel = 0;
      for (int i = primaryNeighbors.Count() - 1; i >= 0; --i) {
        TZone* neighbor = primaryNeighbors[static_cast<unsigned int>(i)];
        neighbor->LightDistanceRecursive(1);
      }
    }

    for (TZone* writeNode = g_pMapActionContextListHead; writeNode != 0;
         writeNode = writeNode->prevZone) {
      short nodeOrd = writeNode != 0 ? writeNode->contextOrdinal : -1;
      cache = static_cast<char*>(g_pMapActionContextDistanceCache);
      cache[thisOrd * g_nMapActionContextCount + nodeOrd] =
          static_cast<char>(writeNode->distanceLevel);
      cache[nodeOrd * g_nMapActionContextCount + thisOrd] =
          static_cast<char>(writeNode->distanceLevel);
    }

    cache = static_cast<char*>(g_pMapActionContextDistanceCache);
    cachedDistance = cache[thisOrd * g_nMapActionContextCount + otherOrd];
  }

  return cachedDistance;
}

// FUNCTION: IMPERIALISM 0x00561380
int TZone::CountEnemiesPresent(int nation) {
  int count = 0;
  for (int slot = 0; slot < 7; ++slot) {
    if (g_apTerrainTypeDescriptorTable[slot] != 0) {
      unsigned char nationBit = 1 << static_cast<short>(slot);
      if ((static_cast<unsigned char>(nationKeyMask) & nationBit) != 0 &&
          g_pDiplomacyTurnStateManager->AreAtWar(nation, slot)) {
        ++count;
      }
    }
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x00561400
unsigned int TZone::GetPatrolMaskWith(unsigned char nation) {
  unsigned int mask = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this) {
      TTaskForce* entry = ship->taskForce;
      if (entry != 0 && entry->defeated == 0 &&
          (entry->shipOrders == 3 || entry->shipOrders == 4)) {
        mask |= 1u << (ship->nation & 0x1f);
      }
    }
  }
  return (1u << (nation & 0x1f)) | mask;
}

// FUNCTION: IMPERIALISM 0x00561490
unsigned int TZone::GetPatrolMask() {
  unsigned int mask = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this) {
      TTaskForce* entry = ship->taskForce;
      if (entry != 0 && entry->defeated == 0 &&
          (entry->shipOrders == 3 || entry->shipOrders == 4)) {
        mask |= 1u << (ship->nation & 0x1f);
      }
    }
  }
  return mask;
}

// FUNCTION: IMPERIALISM 0x00561510
unsigned int TZone::HasEnemyPatrol(int nation) {
  unsigned int mask = 0;
  for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
    if (ship->location == this) {
      TTaskForce* entry = ship->taskForce;
      if (entry != 0 && entry->defeated == 0 &&
          (entry->shipOrders == 3 || entry->shipOrders == 4)) {
        mask |= 1u << (ship->nation & 0x1f);
      }
    }
  }
  if ((mask & (1u << (static_cast<unsigned char>(nation) & 0x1f))) != 0) {
    return 0;
  }
  int candidate = 0;
  while ((mask & (1u << (candidate & 0x1f))) == 0 ||
         !g_pDiplomacyTurnStateManager->AreInEstablishedWar(candidate, nation)) {
    ++candidate;
    if (candidate > 6) {
      return 0;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005619e0
void TZone::ResolvePortZoneOwnerContextAndDispatch() {
  short tileIndex = PickPennantIngotTile();
  short ownerNation = g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag;
  TZone* contextElement = &g_pActiveMapOrderContext->contextArray[ownerNation - 0x17];
  primaryNeighbors.Add(contextElement);
  contextElement->primaryNeighbors.Add(this);
}

// FUNCTION: IMPERIALISM 0x00561b90
short TZone::GetPortOwnerNation() {
  short tileIndex = static_cast<TPortZone*>(this)->portTileIndex;
  return g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag;
}

// FUNCTION: IMPERIALISM 0x00561bf0
TZone* TZone::FindPortZoneByTile(short nTileIndex) {
  TZone* zone = g_pMapActionContextListHead;
  while (zone != 0 && zone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    zone = zone->prevZone;
  }
  for (;;) {
    if (zone == 0) {
      return 0;
    }
    if (static_cast<short>(zone->tileOrTerrainId) == nTileIndex ||
        zone->activeTileIndex == nTileIndex ||
        static_cast<TPortZone*>(zone)->portTileIndex == nTileIndex) {
      return zone;
    }
    zone = zone->prevZone;
    while (zone != 0 && zone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      zone = zone->prevZone;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00561c80
TZone* TZone::GetFirstPort() {
  TZone* cursor = g_pMapActionContextListHead;
  while (cursor != 0 && cursor->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    cursor = cursor->prevZone;
  }
  return cursor;
}

// FUNCTION: IMPERIALISM 0x00561d40
TZone* TZone::GetNextPort() {
  TZone* cursor = prevZone;
  while (cursor != 0 && cursor->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    cursor = cursor->prevZone;
  }
  return cursor;
}

// Unlinks this zone from the map-action context list; members tear down automatically.

// FUNCTION: IMPERIALISM 0x005627a0
TZone::~TZone() {
  Vanish();
}

// FUNCTION: IMPERIALISM 0x00563220
void RegenerateZoneCodes(void) {
  const char* tag = g_pGlobalMapState->scenarioTagText;
  int seed = kControlTagNada;
  while (*tag != '\0') {
    seed = (seed >> 0x10) + seed * 2 + static_cast<int>(*tag);
    ++tag;
  }
  g_zoneStatusCodePrngSeed = seed;
  if (seed == 0) {
    g_zoneStatusCodePrngSeed = ClockDerivedPrngSeed();
  }
  g_mapActionContextDisplayNameCacheId = -1;

  unsigned char statusScratch[kProvinceCount];
  memset(statusScratch, 0, sizeof(statusScratch));

  for (TZone* node = g_pMapActionContextListHead; node != 0; node = node->prevZone) {
    node->GenerateZoneStatusCodeIfUnset();
    node->NameThyself(statusScratch, 0);
  }

  g_zoneStatusCodePrngSeed = 0;
  g_zoneStatusCodePrngSeed = ClockDerivedPrngSeed();
}

// FUNCTION: IMPERIALISM 0x00563da0
void LinkPortZones(void) {
  int tileIndex = 0;
  do {
    TZone* context;
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    short marker = tile.tileActionState;
    if (marker == kMapTileActionStateAnchor || marker == kMapTileActionStateDockedFleet) {
      // Inlined FindPortZoneByTile(tileIndex): match a port zone by any of its tile ids.
      context = TZone::GetFirstPort();
      while (context != 0) {
        short ti = tileIndex;
        if (static_cast<short>(context->tileOrTerrainId) == ti || context->activeTileIndex == ti ||
            static_cast<TPortZone*>(context)->portTileIndex == ti) {
          break;
        }
        context = context->GetNextPort();
      }
    } else {
      short region = tile.ownerNationTag;
      if (region >= 0x17) {
        context = &g_pActiveMapOrderContext->contextArray[region - 0x17];
      } else {
        context = 0;
      }
    }

    if (context != 0) {
      for (int direction = 0; direction < 6; ++direction) {
        short neighborTile =
            TMapMgr::StepTile(static_cast<short>(tileIndex), static_cast<short>(direction));
        if (neighborTile != -1) {
          short cityIdx = g_pGlobalMapState->terrainStateTable[neighborTile].cityRecordIndex;
          Province* cityRecord;
          if (cityIdx == -1) {
            cityRecord = 0;
          } else {
            cityRecord = &g_pGlobalMapState->cityScoreTable[cityIdx];
          }
          if (cityRecord != 0) {
            // Append the neighbour's city context to the secondary list if not already present.
            Province** match = 0;
            if (context->secondaryNeighbors.Count() != 0) {
              Province** entries = context->secondaryNeighbors.Data();
              unsigned int j = 0;
              Province** scan = entries;
              do {
                if (*scan == cityRecord) {
                  match = entries + j;
                  break;
                }
                ++j;
                ++scan;
              } while (j < static_cast<unsigned int>(context->secondaryNeighbors.Count()));
            }
            if (match == 0) {
              context->secondaryNeighbors.Add(cityRecord);
            }
          }
        }
      }
    }

    ++tileIndex;
  } while (static_cast<short>(tileIndex) < kStrategicTileCount);
}

// FUNCTION: IMPERIALISM 0x00563f50
void RefreshPortLinks(void) {
  for (int tileIndex = 0; static_cast<short>(tileIndex) < kStrategicTileCount; ++tileIndex) {
    TTerrainStateRecord& tileRecord = g_pGlobalMapState->terrainStateTable[tileIndex];
    TZone* zone;
    if (tileRecord.tileActionState == kMapTileActionStateAnchor ||
        tileRecord.tileActionState == kMapTileActionStateDockedFleet) {
      zone = TZone::FindPortZoneByTile(static_cast<short>(tileIndex));
    } else if (tileRecord.ownerNationTag >= kNationSlotCount) {
      zone = &g_pActiveMapOrderContext->contextArray[tileRecord.ownerNationTag - 0x17];
    } else {
      zone = 0;
    }

    if (zone != 0 && zone->IsPortZone()) {
      if (zone->primaryNeighbors.Count() == 0) {
        short tileIdx = zone->tileOrTerrainId;
        short ownerNation = g_pGlobalMapState->terrainStateTable[tileIdx].ownerNationTag;
        TZone* contextElement = &g_pActiveMapOrderContext->contextArray[ownerNation - 0x17];
        zone->primaryNeighbors.Add(contextElement);
        contextElement->primaryNeighbors.Add(zone);
      }
    } else if (zone != 0) {
      for (int direction = 0; direction < 6; ++direction) {
        short neighborTile =
            TMapMgr::StepTile(static_cast<short>(tileIndex), static_cast<short>(direction));
        if (neighborTile == -1) {
          continue;
        }

        TTerrainStateRecord& neighborRecord = g_pGlobalMapState->terrainStateTable[neighborTile];
        if (neighborRecord.cityRecordIndex != -1) {
          Province* candidate = &g_pGlobalMapState->cityScoreTable[neighborRecord.cityRecordIndex];
          if (!zone->secondaryNeighbors.ContainsEntry(candidate)) {
            zone->secondaryNeighbors.Add(candidate);
          }
          continue;
        }

        TZone* candidateContext;
        if (neighborRecord.tileActionState == kMapTileActionStateAnchor ||
            neighborRecord.tileActionState == kMapTileActionStateDockedFleet) {
          // Inlined FindPortZoneByTile(neighborTile): match a port zone by any of its tile ids.
          candidateContext = TZone::GetFirstPort();
          while (candidateContext != 0) {
            if (static_cast<short>(candidateContext->tileOrTerrainId) == neighborTile ||
                candidateContext->activeTileIndex == neighborTile ||
                static_cast<TPortZone*>(candidateContext)->portTileIndex == neighborTile) {
              break;
            }
            candidateContext = candidateContext->GetNextPort();
          }
        } else if (neighborRecord.ownerNationTag >= kNationSlotCount) {
          candidateContext =
              &g_pActiveMapOrderContext->contextArray[neighborRecord.ownerNationTag - 0x17];
        } else {
          candidateContext = 0;
        }

        if (candidateContext != 0 && candidateContext != zone && !candidateContext->IsPortZone() &&
            !zone->primaryNeighbors.ContainsEntry(candidateContext)) {
          zone->primaryNeighbors.Add(candidateContext);
        }
      }
    }
  }
}
