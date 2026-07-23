#include <time.h>

#include "game/map/TMapMgr.h"

#include "game/map_ui/TMapMaker.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/assets/TAssetMgr.h"
#include "game/military/mapped_flavor_text.h"

#include "game/ui_core/CIterator.h"
#include "game/ui_screens/CString.h"
#include "game/military/TArmyMgr.h"
#include "game/city_ui/TCivMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TSortedList.h"
#include "game/nation/TMinor.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_screens/TPortZone.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TZone.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/city/TCity.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ImperialismApp.h"
#include "game/globals/prelude.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"

#include <cstdio>
#include "game/ui_widgets/TTradeMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_widgets/TTown.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/gfx/ui_invalidation_guard.h"

StrategicTileIndex TraceTerrainFlowToNearestSeaTile(StrategicTileIndex tileIndex);
char __stdcall EvaluateTerrainFlowCrossNationBoundaryToSea(StrategicTileIndex tileIndex);
void NormalizeWrappedMapCoord217x60(short* xCoord, short* yCoord);

// FUNCTION: IMPERIALISM 0x004a4190
TMilitaryUnit* TMapMgr::ValidateGridIndexRange0To17F(short index) {
  if (index < 0 || index >= 0x180) {
    return nullptr;
  }
  return cityScoreTable[index].stationedUnitChain98;
}

// Hex direction (0-6) from sourceTile to destTile on the 0x6c(108)-wide map, via each tile's
// doubled-hex-coordinate ("diagonal") position: diag = (row & 1) + col*2. Ghidra's decompile
// hand-emulates row/col with a magic-multiply division and a sign-correcting parity dance for
// negative row indices; map tile indices are never negative in practice, so that correction
// collapses to a plain `row & 1` here (a faithful simplification, not a shortcut of behavior).

// SYNTHETIC: IMPERIALISM 0x0050e2f0
// TMapMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x0050e3b0
// TMapMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapMgr, TObject)

// FUNCTION: IMPERIALISM 0x0050e3d0
TMapMgr::TMapMgr() : TObject(), cityScoreTable(0), scenarioTagText1c() {
  field8 = 0;
  strategicMapPalettePreviewReady04 = 0;
  terrainStateTable = 0;
  field9 = 1;
  field24 = 0;
  pendingRiverMouthTile22 = -1;
}

// SYNTHETIC: IMPERIALISM 0x0050e460
// TMapMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0050e490
TMapMgr::~TMapMgr() {}

// FUNCTION: IMPERIALISM 0x0050e4e0
void TMapMgr::InitializeGlobalMapState() {
  field6 = 1;
  if (g_pStrategicMapViewSystem->atlas668 == 0) {
    g_pStrategicMapViewSystem->BuildStrategicMapRenderAtlasesAndTileMaskCaches();
  }
}

// FUNCTION: IMPERIALISM 0x0050e510
void TMapMgr::Free() {
  delete[] terrainStateTable;
  delete[] cityScoreTable;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0050e620
void TMapMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&field6, 2);
  stream->ReadBytes(&field8, 1);
  stream->ReadBytes(&field9, 1);
  stream->ReadBytes(&cityScoreTotal, 4);
  stream->streamSlot70(&scenarioTagText1c, 0x20);
  hexNeighborWrapHorizontally20 = stream->streamSlot44();
  stream->ReadBytes(terrainStateTable, 0x38f40);
  int i;
  Province* record = cityScoreTable;
  for (i = 0; i < 0x180; ++i, ++record) {
    stream->ReadBytes(record, 0xa4);
    stream->streamSlot70(&record->cityNameA4, 0x20);
  }
  for (i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].firstCivilianOrder20 = nullptr;
  }
  for (i = 0; i < 0x180; ++i) {
    cityScoreTable[i].stationedUnitChain98 = nullptr;
  }
  strategicMapPalettePreviewReady04 = 0;
  if (g_nSaveFormatVersion < 0x32) {
    for (i = 0; i < 0x1950; ++i) {
      terrainStateTable[i].perTileVisitedFlag0f = 0;
    }
  }
  if (g_nSaveFormatVersion > 0x32) {
    stream->ReadBytes(&pendingRiverMouthTile22, 2);
  } else {
    pendingRiverMouthTile22 = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0050e7a0
void TMapMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&field6, 2);
  stream->WriteBytesSlot78(&field8, 1);
  stream->WriteBytesSlot78(&field9, 1);
  stream->WriteBytesSlot78(&cityScoreTotal, 4);
  stream->streamSlotAc(&scenarioTagText1c);
  stream->streamSlot80(hexNeighborWrapHorizontally20);
  stream->WriteBytesSlot78(terrainStateTable, 0x38f40);
  Province* record = cityScoreTable;
  for (int i = 0; i < 0x180; ++i, ++record) {
    stream->WriteBytesSlot78(record, 0xa4);
    stream->streamSlotAc(&record->cityNameA4);
  }
  stream->WriteBytesSlot78(&pendingRiverMouthTile22, 2);
}

// FUNCTION: IMPERIALISM 0x0050e8b0
void TMapMgr::AllocateAndResetTerrainAndCityScoreTables() {
  if (terrainStateTable == 0) {
    terrainStateTable = new TTerrainStateRecordView[0x1950];
    if (terrainStateTable == 0) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0x198);
    }
  }
  int i;
  for (i = 0; i < 0x1950; ++i) {
    TTerrainStateRecordView* tile = &terrainStateTable[i];
    tile->SetTerrainKind(kStrategicTerrainUnassigned);
    tile->spriteVariantIndex01 = 0;
    tile->riverSpriteCode = kRiverSpriteCodeNone;
    tile->formerOwnerNationTag03 = -1;
    tile->ownerNationTag04 = -1;
    tile->regionSubtypeTag05 = -1;
    tile->adjacencyBits06 = 0;
    tile->ownerBorderMask07 = 0;
    tile->cityBorderMask08 = 0;
    tile->waterAdjacencyMask09 = 0;
    tile->adjacencyMaskA0a = 0;
    tile->adjacencyMaskB0b = 0;
    tile->developmentClassNibbles0c = 0;
    tile->pendingDevelopmentFlag0d = 0;
    tile->perTileVisitedFlag0f = 0;
    tile->resourceTypeByEdge[0] = -1;
    tile->resourceTypeByEdge[1] = -1;
    tile->gateFlag = -1;
    tile->cityRecordIndex = -1;
    tile->tileActionState16 = kMapTileActionStateNone;
    tile->railFlags17 = 0;
    tile->secondaryOwnerNationTag18 = -1;
    tile->tileActionOrdinal1a = -1;
    tile->activeFlags1c = 0;
    tile->firstCivilianOrder20 = 0;
  }

  if (cityScoreTable == 0) {
    cityScoreTable = new Province[0x180];
    if (cityScoreTable == 0) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0x1c7);
    }
  }
  int j;
  for (i = 0; i < 0x180; ++i) {
    Province* record = &cityScoreTable[i];
    record->ownerNationCode00 = -1;
    record->formerOwnerNationCode01 = -1;
    record->developmentStage = 0;
    record->fortLevel03 = 0;
    record->cityTileIndex04 = -1;
    record->lastTurnTick = 999;
    record->adjacentRegionCount08 = 0;
    for (j = 0; j < 0xc; ++j) {
      record->adjacentRegionIds0A[j] = -1;
    }
    for (j = 0; j < 0xc; ++j) {
      record->adjacentRegionAnchorTiles22[j] = -1;
    }
    record->linkedRegionCount = 0;
    record->byte3B = 0;
    record->byte3C = 0;
    record->secondaryNeighborTileIndex3e = -1;
    record->primaryNeighborTileIndex40 = -1;
    for (j = 0; j < 0x20; ++j) {
      record->linkedTileIndices42[j] = -1;
    }
    record->resourceDevelopmentCounts82[0] = 0;
    record->resourceDevelopmentCounts82[1] = 0;
    record->resourceDevelopmentCounts82[2] = 0;
    record->resourceDevelopmentCounts82[3] = 0;
    record->resourceDevelopmentCounts82[4] = 0;
    record->resourceDevelopmentCounts82[5] = 0;
    record->resourceDevelopmentCounts82[6] = 0;
    record->resourceDevelopmentCounts82[7] = 0;
    record->resourceDevelopmentCounts82[8] = 0;
    record->resourceDevelopmentCounts82[9] = 0;
    record->stationedUnitChain98 = 0;
    record->resourcePresenceMaskA2 = 0;
    record->regionClassA3 = -1;
    record->cityNameA4 = g_szEmptyString;
  }
}

// Builds (or loads) the whole per-session map state. Three entry modes: replay
// (TSimMgr reloadPoliticalMapState set) reloads the political tables and refreshes tiles in place;
// scenario (scenarioMapIndexPlusOne set) loads the fixed map table (returning 0 on failure);
// otherwise a fresh map is generated from the tuning string unless mapStreamName
// names an already-populated stream. Every phase is bracketed by setup-globe spins.
// FUNCTION: IMPERIALISM 0x0050ec90
char TMapMgr::BuildOrLoadGlobalMapStateForSession(const char* mapStreamName, char* tuningOverride) {
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  AllocateAndResetTerrainAndCityScoreTables();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  TMapMaker* mapMaker = new TMapMaker();

  char sessionActive;
  if (g_pSimMgr->reloadPoliticalMapState != 0 || g_pSimMgr->scenarioMapIndexPlusOne != 0) {
    sessionActive = 1;
  } else {
    sessionActive = 0;
  }
  mapMaker->modeByte2a1 = hexNeighborWrapHorizontally20;

  if (sessionActive != 0) {
    if (g_pSimMgr->reloadPoliticalMapState != 0) {
      // Replay path: reload the political tables and refresh every tile in place.
      LoadPoliticalMapRegionSubtypeTableFromResourceStream();
      short tile;
      for (tile = 0; tile < 0x1950; ++tile) {
        UpdateMapTileAdjacencyMasksAndVariantForTile(tile);
        UpdateTileNeighborBorderInfluenceCounters(tile, 0);
      }
      g_pUiRuntimeContext->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventMapEditor), 0);
    } else {
      // Scenario path: load the fixed map; bail out entirely when that fails.
      if (LoadScenarioMapStateFromTableResource(g_pSimMgr->scenarioMapIndexPlusOne - 1) == 0) {
        if (mapMaker != 0) {
          mapMaker->Free();
        }
        Free();
        g_pGlobalMapState = 0;
        return 0;
      }
    }
    mapMaker->mapTileGrid08 = reinterpret_cast<char*>(terrainStateTable);
    mapMaker->MapGenFinalizePassSlot19(1);
  } else if (mapStreamName == 0) {
    if (tuningOverride != 0) {
      CString overrideText(tuningOverride);
      scenarioTagText1c = overrideText;
    } else {
      GenerateMappedFlavorTextByCurrentContextNation(&scenarioTagText1c);
    }
    mapMaker->GenerateMapFromTuningStringAndApplyScenarioOverrides(
        reinterpret_cast<char*>(terrainStateTable), cityScoreTable, &scenarioTagText1c);
  }

  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  if (sessionActive == 0) {
    // Fresh map: stamp the icon variants and snapshot every tile's owner as the
    // former owner.
    short tile;
    for (tile = 0; tile < 0x1950; ++tile) {
      UpdateStrategicMapTileIconVariantState(tile);
      TTerrainStateRecordView& tileRecord = terrainStateTable[tile];
      tileRecord.formerOwnerNationTag03 = tileRecord.ownerNationTag04;
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  RebuildTileOwnerNeighborCachesAndFallbackAssignments();
  if (sessionActive != 0) {
    // Loaded map: assign contiguous region-class codes across the linked city records.
    int nextClassCode = 0;
    int rec;
    for (rec = 0; rec < 0x180; ++rec) {
      Province* record = cityScoreTable + rec;
      if (record->linkedTileIndices42[0] != -1 && record->regionClassA3 == -1) {
        int classCode = nextClassCode;
        ++nextClassCode;
        if (cityScoreTable[rec].regionClassA3 != classCode) {
          record->regionClassA3 = static_cast<char>(classCode);
          int i;
          for (i = 0; i < cityScoreTable[rec].adjacentRegionCount08; ++i) {
            SetMapRecordFlagA3AndPropagateToChildren(cityScoreTable[rec].adjacentRegionIds0A[i],
                                                     classCode);
          }
        }
      }
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  if (sessionActive == 0) {
    GuaranteeResources();
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  mapMaker->RebuildUMapperRouteRecordsAndActiveMapRects();
  g_pSimMgr->ReinitializeRandomSeed();
  g_zoneStatusCodePrngSeed_006a5aec = 0;
  g_zoneStatusCodePrngSeed_006a5aec = time(0);
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  if (sessionActive == 0) {
    short tile;
    for (tile = 0; tile < 0x1950; ++tile) {
      UpdateMapTileAdjacencyMasksAndVariantForTile(tile);
      UpdateTileNeighborBorderInfluenceCounters(tile, 0);
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  g_pUiRuntimeContext->RenderTurnEventPalettePreviewSurfaceAndProgress();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  field8 = 1;
  if (mapMaker != 0) {
    mapMaker->Free();
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0050f200
undefined TMapMgr::LoadPoliticalMapRegionSubtypeTableFromResourceStream() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0050f6b0
void TMapMgr::SetMapRecordFlagA3AndPropagateToChildren(int recordIndex, int classCode) {
  if (cityScoreTable[recordIndex].regionClassA3 != classCode) {
    cityScoreTable[recordIndex].regionClassA3 = static_cast<char>(classCode);
    int i;
    for (i = 0; i < cityScoreTable[recordIndex].adjacentRegionCount08; ++i) {
      SetMapRecordFlagA3AndPropagateToChildren(cityScoreTable[recordIndex].adjacentRegionIds0A[i],
                                               classCode);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0050f740
void TMapMgr::GenerateProvinceNames() {
  // Hash the scenario tag string to seed the zone status-code PRNG.
  const char* tag = scenarioTagText1c;
  int seed = 0x6e616461; // "adan"
  while (*tag != '\0') {
    seed = (seed >> 16) + seed * 2 + static_cast<int>(*tag);
    tag++;
  }
  g_zoneStatusCodePrngSeed_006a5aec = seed;
  if (seed == 0) {
    g_zoneStatusCodePrngSeed_006a5aec = time(0);
  }

  // Reset the localized province-name ordinals, then assign a name to every
  // province record that has at least one linked region.
  CString local_10;
  AssignNextProvinceNameForNationSlot(&local_10, -1);

  for (int i = 0; i < 0x180; i++) {
    Province* record = &cityScoreTable[i];
    if (record->linkedTileIndices42[0] != -1) {
      AssignNextProvinceNameForNationSlot(&record->cityNameA4, record->ownerNationCode00);
    }
  }

  // Reseed the PRNG from the system clock so later status-code generation is
  // non-deterministic.
  g_zoneStatusCodePrngSeed_006a5aec = 0;
  g_zoneStatusCodePrngSeed_006a5aec = time(0);
}

// FUNCTION: IMPERIALISM 0x0050f860
void TMapMgr::RebuildTileOwnerNeighborCachesAndFallbackAssignments() {
  // Phase 1: append every land tile to its owning city record's linkedTileIndices list
  // (AllocateAndResetTerrainAndCityScoreTables left the lists empty).
  short tile;
  for (tile = 0; tile < 0x1950; ++tile) {
    if (terrainStateTable[tile].GetTerrainKind() != kStrategicTerrainWater) {
      StrategicTileIndex tileIndex = tile;
      short cityRec = g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex;
      cityScoreTable[cityRec].linkedTileIndices42[cityScoreTable[cityRec].linkedRegionCount] =
          tileIndex;
      ++cityScoreTable[cityRec].linkedRegionCount;
    }
  }

  // Phase 2: per record, derive the owner nation from the first linked tile, rebuild the
  // adjacent-record id/anchor-tile pairs and the resource-presence mask, pick a fallback
  // city tile when none is anchored, and recount the adjacency list.
  int recIndex;
  for (recIndex = 0; recIndex < 0x180; ++recIndex) {
    Province* record = &cityScoreTable[recIndex];
    if (record->linkedTileIndices42[0] != -1) {
      signed char owner =
          g_pGlobalMapState->terrainStateTable[record->linkedTileIndices42[0]].ownerNationTag04;
      record->formerOwnerNationCode01 = owner;
      record->ownerNationCode00 = owner;

      short interiorTiles[0x20];
      short interiorCount = 0;
      if (record->linkedRegionCount > 0) {
        int i = 0;
        const StrategicTileIndex* linkedTile = record->linkedTileIndices42;
        for (i = 0; i < record->linkedRegionCount; ++i) {
          char hasForeignNeighbor = 0;
          short neighbors[6];
          GetNeighborTileIDArray(*linkedTile, neighbors, hexNeighborWrapHorizontally20);

          int d;
          const short* neighborWalker = neighbors;
          for (d = 6; d != 0; --d) {
            StrategicTileIndex neighborTile = *neighborWalker;
            if (neighborTile != -1) {
              short neighborRec = terrainStateTable[neighborTile].cityRecordIndex;
              if (neighborRec != recIndex && neighborRec != -1) {
                char inserted = 0;
                hasForeignNeighbor = 1;
                int k = 0;
                short* slot = record->adjacentRegionIds0A;
                while (inserted == 0) {
                  if (*slot == -1) {
                    *slot = neighborRec;
                    inserted = 1;
                    slot[0xc] = neighborTile;
                  } else if (*slot == neighborRec) {
                    inserted = 1;
                  }
                  ++k;
                  ++slot;
                  if (k >= 0xc) {
                    break;
                  }
                }
              }
            }
            ++neighborWalker;
          }

          if (hasForeignNeighbor == 0) {
            interiorTiles[interiorCount] = *linkedTile;
            ++interiorCount;
          }

          int edge;
          for (edge = 0; edge < 2; ++edge) {
            char resourceType =
                g_pGlobalMapState->terrainStateTable[*linkedTile].resourceTypeByEdge[edge];
            if (resourceType != -1) {
              record->resourcePresenceMaskA2 |= static_cast<unsigned char>(1 << resourceType);
            }
          }
          ++linkedTile;
        }
      }

      if (record->cityTileIndex04 == -1) {
        short chosenTile;
        if (interiorCount == 0) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          chosenTile =
              record
                  ->linkedTileIndices42[static_cast<int>(g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) %
                                        record->linkedRegionCount];
        } else {
          // Prefer plains and farmland among the interior tiles.
          short flatTiles[0x18];
          short flatCount = 0;
          int j = interiorCount;
          if (j > 0) {
            const short* interiorWalker = interiorTiles;
            do {
              short candidate = *interiorWalker;
              StrategicTerrainKind terrainKind =
                  g_pGlobalMapState->terrainStateTable[candidate].GetTerrainKind();
              if (terrainKind == kStrategicTerrainPlains ||
                  terrainKind == kStrategicTerrainFarmland) {
                flatTiles[flatCount] = candidate;
                ++flatCount;
              }
              ++interiorWalker;
              --j;
            } while (j != 0);
          }
          if (flatCount != 0) {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            chosenTile =
                flatTiles[static_cast<int>(g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % flatCount];
          } else {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            chosenTile = interiorTiles[static_cast<int>(g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) %
                                       interiorCount];
          }
        }
        InitializeTileNeighborConnectionMaskIfNeeded(chosenTile);
        cityScoreTable[recIndex].cityTileIndex04 = chosenTile;
        terrainStateTable[chosenTile].activeFlags1c = 2;
        terrainStateTable[chosenTile].activeFlags1c |= 0x20;
      }

      UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(recIndex);

      record->adjacentRegionCount08 = 0;
      if (record->adjacentRegionIds0A[0] != -1) {
        for (;;) {
          signed char count = record->adjacentRegionCount08;
          if (count >= 0xc) {
            break;
          }
          ++count;
          record->adjacentRegionCount08 = count;
          if (record->adjacentRegionIds0A[count] == -1) {
            break;
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0050fca0
void TMapMgr::UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(ProvinceIndex cityRecordIndex) {
  short neighbors[6];
  GetNeighborTileIDArray(cityScoreTable[cityRecordIndex].cityTileIndex04, neighbors,
                         hexNeighborWrapHorizontally20);

  bool consumed[6] = {false, false, false, false, false, false};
  int d;

  int bestDirection = -1;
  short bestPriority = 1;
  for (d = 0; d < 6; ++d) {
    if (neighbors[d] != -1) {
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (neighbor->cityRecordIndex == cityRecordIndex) {
        if (bestPriority < g_anStrategicTerrainNeighborLinkPriority[neighbor->GetTerrainKind()]) {
          bestDirection = d;
          bestPriority = g_anStrategicTerrainNeighborLinkPriority[neighbor->GetTerrainKind()];
        }
      }
    }
  }
  consumed[bestDirection] = true;
  cityScoreTable[cityRecordIndex].primaryNeighborTileIndex40 = neighbors[bestDirection];

  int secondDirection = -1;
  short secondPriority = -1;
  for (d = 0; d < 6; ++d) {
    if (neighbors[d] != -1 && !consumed[d]) {
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      short priority = g_anStrategicTerrainNeighborLinkPriority[neighbor->GetTerrainKind()];
      if (neighbor->cityRecordIndex == cityRecordIndex) {
        priority += 0x14;
      }
      if (secondPriority < priority) {
        secondDirection = d;
        secondPriority = priority;
      }
    }
  }
  consumed[secondDirection] = true;
  cityScoreTable[cityRecordIndex].secondaryNeighborTileIndex3e = neighbors[secondDirection];
}

// Hex-direction bit flags (1 << dir). Ground truth reads this via
// `(char*)g_Build_Hex_Area_LookupTable_00696E80 + N`, but that offset lands well past that
// global's own declared 6-short extent (0x696e80..0x696e8b) -- it's really a distinct,
// separately-emitted 6-entry const table that happens to sit shortly after it in the
// original .rdata layout, not guaranteed to hold in a freshly linked recompile. Modeled here
// as its own bounds-safe table instead of pointer-walking off an unrelated global.
static const unsigned char kHexDirectionBitMask[6] = {1, 2, 4, 8, 16, 32};

// The "next" hex direction (d+1 mod 6), read raw at 0x00696e30 as its own table rather than
// computed by TMapMgr::UpdateTileNeighborBorderInfluenceCounters (0x50fe10) -- the original
// does a table lookup here, not a division, so this is modeled the same way.
static const short kNextHexDirection[6] = {1, 2, 3, 4, 5, 0};

// FUNCTION: IMPERIALISM 0x0050fe10
void TMapMgr::UpdateTileNeighborBorderInfluenceCounters(StrategicTileIndex tileIndex, short mode) {
  short neighbors[6];
  GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally20);

  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  bool isWater = tile->GetTerrainKind() == kStrategicTerrainWater;

  for (int d = 0; d < 6; ++d) {
    StrategicTileIndex neighborTile = neighbors[d];
    if (neighborTile == -1) {
      tile->ownerBorderMask07 += kHexDirectionBitMask[d];
      continue;
    }
    TTerrainStateRecordView* neighbor = &terrainStateTable[neighborTile];
    if (isWater) {
      if (mode == 0 && neighbor->GetTerrainKind() == kStrategicTerrainWater &&
          neighbor->ownerNationTag04 != tile->ownerNationTag04) {
        tile->ownerBorderMask07 += kHexDirectionBitMask[d];
      }
    } else if (neighbor->GetTerrainKind() == kStrategicTerrainWater) {
      tile->waterAdjacencyMask09 += kHexDirectionBitMask[d];
    } else {
      if (neighbor->ownerNationTag04 != tile->ownerNationTag04) {
        tile->ownerBorderMask07 += kHexDirectionBitMask[d];
      }
      if (mode != 2 && neighbor->cityRecordIndex != tile->cityRecordIndex) {
        tile->cityBorderMask08 += kHexDirectionBitMask[d];
      }
    }
  }

  if (isWater) {
    for (int d = 0; d < 6; ++d) {
      short neighborA = neighbors[d];
      short neighborB = neighbors[kNextHexDirection[d]];
      if (neighborA == -1 || neighborB == -1) {
        continue;
      }
      TTerrainStateRecordView* tileA = &terrainStateTable[neighborA];
      TTerrainStateRecordView* tileB = &terrainStateTable[neighborB];
      if (tileA->GetTerrainKind() == kStrategicTerrainWater ||
          tileB->GetTerrainKind() == kStrategicTerrainWater) {
        continue;
      }
      if (tileA->ownerNationTag04 != tileB->ownerNationTag04) {
        tile->ownerBorderMask07 += kHexDirectionBitMask[d];
      }
      if (mode != 2 && tileA->cityRecordIndex != tileB->cityRecordIndex) {
        tile->cityBorderMask08 += kHexDirectionBitMask[d];
      }
    }
  }

  if (mode != 2) {
    unsigned char cityMask = tile->cityBorderMask08;
    if ((cityMask & 2) && (cityMask & 1) && neighbors[1] != -1 && neighbors[0] != -1 &&
        terrainStateTable[neighbors[1]].cityRecordIndex !=
            terrainStateTable[neighbors[0]].cityRecordIndex) {
      tile->cityBorderMask08 = cityMask + 0x40;
    }
    cityMask = tile->cityBorderMask08;
    if ((cityMask & 2) && (cityMask & 4) && neighbors[1] != -1 && neighbors[2] != -1 &&
        terrainStateTable[neighbors[1]].cityRecordIndex !=
            terrainStateTable[neighbors[2]].cityRecordIndex) {
      tile->cityBorderMask08 = cityMask + 0x80;
    }
  }

  unsigned char ownerMask = tile->ownerBorderMask07;
  if ((ownerMask & 2) && (ownerMask & 1) && neighbors[1] != -1 && neighbors[0] != -1 &&
      terrainStateTable[neighbors[1]].ownerNationTag04 !=
          terrainStateTable[neighbors[0]].ownerNationTag04) {
    tile->ownerBorderMask07 = ownerMask + 0x40;
  }
  ownerMask = tile->ownerBorderMask07;
  if ((ownerMask & 2) && (ownerMask & 4) && neighbors[1] != -1 && neighbors[2] != -1 &&
      terrainStateTable[neighbors[1]].ownerNationTag04 !=
          terrainStateTable[neighbors[2]].ownerNationTag04) {
    tile->ownerBorderMask07 = ownerMask + 0x80;
  }
}

// Opposite hex direction (d+3 mod 6), read raw at 0x00696e60 as its own table by
// TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded (0x5107e0) rather than computed --
// modeled the same way per the kNextHexDirection precedent above (table lookup, not modulo).
static const short kOppositeHexDirection[6] = {3, 4, 5, 0, 1, 2};

// Byte-swap one big-endian short in place (the scenario table resources are Mac-order;
// the original inlines this two-byte exchange at every fixup site).
static __inline void SwapShortBytes(void* value) {
  char* bytes = static_cast<char*>(value);
  char low = bytes[0];
  char high = bytes[1];
  bytes[0] = high;
  bytes[1] = low;
}

// FUNCTION: IMPERIALISM 0x00510210
unsigned char* TMapMgr::UpdateMapTileAdjacencyMasksAndVariantForTile(StrategicTileIndex tileIndex) {
  short neighbors[6];
  unsigned char* result;

  if (terrainStateTable[tileIndex].GetTerrainKind() != kStrategicTerrainWater) {
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally20);
    result = reinterpret_cast<unsigned char*>(terrainStateTable);
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] != -1 &&
          terrainStateTable[neighbors[d]].gateFlag == terrainStateTable[tileIndex].gateFlag) {
        terrainStateTable[tileIndex].adjacencyMaskA0a |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
      }
    }
    if (terrainStateTable[tileIndex].GetTerrainKind() == kStrategicTerrainHills) {
      for (int d = 0; d < 6; ++d) {
        if (neighbors[d] != -1) {
          if (terrainStateTable[neighbors[d]].GetTerrainKind() == kStrategicTerrainMountain) {
            terrainStateTable[tileIndex].adjacencyMaskB0b |=
                (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          }
          if (terrainStateTable[neighbors[d]].GetTerrainKind() == kStrategicTerrainHills) {
            terrainStateTable[tileIndex].adjacencyMaskA0a |=
                (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          }
        }
      }
    }
    if (terrainStateTable[tileIndex].GetTerrainKind() == kStrategicTerrainMountain) {
      for (int d = 0; d < 6; ++d) {
        if (neighbors[d] != -1 &&
            terrainStateTable[neighbors[d]].GetTerrainKind() == kStrategicTerrainHills) {
          terrainStateTable[tileIndex].adjacencyMaskB0b |=
              (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        }
      }
    }
    if (terrainStateTable[tileIndex].GetTerrainKind() == kStrategicTerrainMountain) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      result = 0;
      if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
        result = reinterpret_cast<unsigned char*>(terrainStateTable);
        terrainStateTable[tileIndex].spriteVariantIndex01 = 1;
      }
    }
    if (terrainStateTable[tileIndex].gateFlag == 0xb) {
      for (short d = 0; d < 6; ++d) {
        if (terrainStateTable[neighbors[d]].gateFlag != 0xb) {
          continue;
        }
        short next = (d == 5) ? 0 : (short)(d + 1);
        short prev = (d != 0) ? (short)(d - 1) : 5;
        unsigned char prevTag = terrainStateTable[neighbors[prev]].gateFlag;
        if (prevTag == 0xb) {
          goto check_prevb;
        }
        if (terrainStateTable[neighbors[next]].gateFlag == 0xb) {
          goto check_pb_nb;
        }
        terrainStateTable[tileIndex].spriteVariantIndex01 = 0;
        continue;
      check_pb_nb:
        if (prevTag != 0xb) {
          goto check_next3;
        }
      check_prevb:
        if (terrainStateTable[neighbors[next]].gateFlag != 0xb) {
          goto check_pb2;
        }
        terrainStateTable[tileIndex].spriteVariantIndex01 = 1;
        continue;
      check_pb2:
        if (prevTag != 0xb) {
          goto check_next3;
        }
        if (terrainStateTable[neighbors[next]].gateFlag == prevTag) {
          if (prevTag == 0xb) {
            continue;
          }
        }
        terrainStateTable[tileIndex].spriteVariantIndex01 = 2;
        continue;
      check_next3:
        if (terrainStateTable[neighbors[next]].gateFlag != 0xb) {
          continue;
        }
        terrainStateTable[tileIndex].spriteVariantIndex01 = 3;
      }
    }
    RiverSpriteCodeStorage variant = terrainStateTable[tileIndex].riverSpriteCode;
    if (variant != 0) {
      if ((variant & 0x80) == 0) {
        int resolved = ResolveMapTileVariantSpriteFromAdjacencyState(tileIndex);
        terrainStateTable[tileIndex].riverSpriteCode =
            static_cast<RiverSpriteCodeStorage>(resolved);
      } else {
        terrainStateTable[tileIndex].riverSpriteCode =
            static_cast<RiverSpriteCodeStorage>(variant & ~kRiverSpriteCodeNeedsResolution);
      }
    }
    RiverSpriteCodeStorage finalVariant = terrainStateTable[tileIndex].riverSpriteCode;
    result = reinterpret_cast<unsigned char*>((unsigned int)(unsigned char)finalVariant);
    if (0x1a < finalVariant && finalVariant < 0x2b) {
      terrainStateTable[tileIndex].riverSpriteCode = finalVariant - 0x10;
      return reinterpret_cast<unsigned char*>((unsigned int)(unsigned char)(finalVariant - 0x10));
    }
  } else {
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally20);
    unsigned int lcg = g_mapGenLcgState_006a38e8;
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] != -1 &&
          terrainStateTable[neighbors[d]].GetTerrainKind() != kStrategicTerrainWater) {
        terrainStateTable[tileIndex].adjacencyMaskB0b |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        lcg = g_mapGenLcgState_006a38e8;
        if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
          terrainStateTable[tileIndex].spriteVariantIndex01 |=
              (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          lcg = g_mapGenLcgState_006a38e8;
        }
      }
    }
    result = reinterpret_cast<unsigned char*>(terrainStateTable);
    if (terrainStateTable[tileIndex].adjacencyMaskB0b != 0) {
      RiverSpriteCodeStorage variant = terrainStateTable[tileIndex].riverSpriteCode;
      result = &terrainStateTable[tileIndex].riverSpriteCode;
      if (variant == 0) {
        return result;
      }
      if ((variant & 0x80) == 0) {
        int resolved = ResolveMapTileVariantSpriteFromAdjacencyState(tileIndex);
        terrainStateTable[tileIndex].riverSpriteCode =
            static_cast<RiverSpriteCodeStorage>(resolved);
        return reinterpret_cast<unsigned char*>(resolved);
      }
      *result = variant & 0x7f;
      return result;
    }
    if (neighbors[4] == -1) {
      return result;
    }
    if (terrainStateTable[neighbors[4]].spriteVariantIndex01 != 0) {
      return result;
    }
    if (((neighbors[5] == -1) || (terrainStateTable[neighbors[5]].spriteVariantIndex01 == 0)) &&
        ((neighbors[0] == -1) || (terrainStateTable[neighbors[0]].spriteVariantIndex01 == 0))) {
      g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
      unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      result = reinterpret_cast<unsigned char*>(roll / 100);
      if (3 < roll % 100) {
        return result;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      terrainStateTable[tileIndex].spriteVariantIndex01 =
          (unsigned char)((g_mapGenLcgState_006a38e8 >> 0xc) & 3) + 1;
      if (pendingRiverMouthTile22 != -1) {
        return result;
      }
      pendingRiverMouthTile22 = tileIndex;
      return reinterpret_cast<unsigned char*>(tileIndex & 0xffff);
    }
    g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = reinterpret_cast<unsigned char*>(roll / 100);
    if (7 < roll % 100) {
      return result;
    }
    char v;
    if (neighbors[5] != -1) {
      v = terrainStateTable[neighbors[5]].spriteVariantIndex01;
      if (v != 0) {
        terrainStateTable[tileIndex].spriteVariantIndex01 = v + 1;
        v = terrainStateTable[tileIndex].spriteVariantIndex01;
        result =
            reinterpret_cast<unsigned char*>(&terrainStateTable[tileIndex].spriteVariantIndex01);
        if (v != 0) {
          if (v < 5) {
            return result;
          }
          *result = 1;
          return result;
        }
        goto assign_river_mouth_one;
      }
    }
    if (neighbors[0] != -1) {
      terrainStateTable[tileIndex].spriteVariantIndex01 =
          terrainStateTable[neighbors[0]].spriteVariantIndex01 + 1;
      v = terrainStateTable[tileIndex].spriteVariantIndex01;
      result = reinterpret_cast<unsigned char*>(&terrainStateTable[tileIndex].spriteVariantIndex01);
      if ((v == 0) || (4 < v)) {
      assign_river_mouth_one:
        *result = 1;
        return result;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005107e0
void TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded(int tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  if (tile->gateFlag == 1) {
    return;
  }

  tile->SetTerrainKind(kStrategicTerrainPlains);
  tile->resourceTypeByEdge[0] = -1;
  tile->resourceTypeByEdge[1] = -1;
  tile->resourceTypeByEdge[0] = 0x11;
  tile->gateFlag = static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(tileIndex));

  short neighbors[6];
  GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally20);
  for (int d = 0; d < 6; ++d) {
    if (neighbors[d] == -1) {
      continue;
    }
    TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
    int oppositeDirection = kOppositeHexDirection[d];
    if (neighbor->adjacencyMaskA0a & (1 << oppositeDirection)) {
      neighbor->adjacencyMaskA0a -= kHexDirectionBitMask[oppositeDirection];
    }
  }
}

// FUNCTION: IMPERIALISM 0x005108d0
int TMapMgr::ResolveMapTileVariantSpriteFromAdjacencyState(int nTileIndex) {
  short sTileIndex = (short)nTileIndex;
  int iTileIndex = (int)sTileIndex;
  int result = 0;
  TTerrainStateRecordView* tiles = terrainStateTable;
  TTerrainStateRecordView* cur = &tiles[iTileIndex];
  if (cur->GetTerrainKind() != kStrategicTerrainWater) {
    RiverSpriteCodeStorage code = cur->riverSpriteCode;
    switch (code) {
    case 1:
      return 0xb;
    case 2:
      return 0xc;
    case 3:
      code = tiles[(short)(sTileIndex - 1)].riverSpriteCode;
      if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 ||
          code == 0x23 || code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
        return 0xd;
      }
      code = tiles[(short)(sTileIndex - 1)].riverSpriteCode;
      if (code != 0x10 && code != 0x20 && code != 0x12 && code != 0x22 && code != 0x14 &&
          code != 0x24 && code != 0x16 && code != 0x26 && code != 0x2d && code != 0x35) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0xd;
      }
      return 0xe;
    case 4:
      if (iTileIndex % 0x6c != 0x6b) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return 0x10 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
      }
      code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
      if (code == 0xd || code == 0x1d || code == 0x11 || code == 0x21 || code == 0x12 ||
          code == 0x22 || code == 0x17 || code == 0x27 || code == 0x30 || code == 0x38) {
        return 0xf;
      }
      code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
      if (code == 0xe || code == 0x1e || code == 0x13 || code == 0x23 || code == 0x14 ||
          code == 0x24 || code == 0x18 || code == 0x28 || code == 0x31 || code == 0x39) {
        return 0x10;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0xf;
    case 5:
      code = tiles[(short)(sTileIndex - 1)].riverSpriteCode;
      if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 ||
          code == 0x23 || code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
        if (iTileIndex % 0x6c != 0x6b) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return 0x12 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
        }
        code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
        if (code != 0xd && code != 0x1d && code != 0x11 && code != 0x21 && code != 0x12 &&
            code != 0x22 && code != 0x17 && code != 0x27 && code != 0x30 && code != 0x38) {
          return 0x12;
        }
        return 0x11;
      }
      code = tiles[(short)(sTileIndex - 1)].riverSpriteCode;
      if (code == 0x10 || code == 0x20 || code == 0x12 || code == 0x22 || code == 0x14 ||
          code == 0x24 || code == 0x16 || code == 0x26 || code == 0x2d || code == 0x35) {
        if (iTileIndex % 0x6c != 0x6b) {
        lcg_variant_0x14:
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return 0x14 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
        }
        code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
      } else {
        if (iTileIndex % 0x6c != 0x6b) {
          goto lcg_variant_0x14;
        }
        code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
      }
      if (code != 0xd && code != 0x1d && code != 0x11 && code != 0x21 && code != 0x12 &&
          code != 0x22 && code != 0x17 && code != 0x27 && code != 0x30 && code != 0x38) {
        return 0x14;
      }
      return 0x13;
    case 6:
      if (iTileIndex % 0x6c != 0x6b) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return 0x16 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
      }
      code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
      if (code == 0xd || code == 0x1d || code == 0x11 || code == 0x21 || code == 0x12 ||
          code == 0x22 || code == 0x17 || code == 0x27 || code == 0x30 || code == 0x38) {
        return 0x15;
      }
      code = tiles[(short)(sTileIndex - 0x6b)].riverSpriteCode;
      if (code == 0xe || code == 0x1e || code == 0x13 || code == 0x23 || code == 0x14 ||
          code == 0x24 || code == 0x18 || code == 0x28 || code == 0x31 || code == 0x39) {
        return 0x16;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x15;
    case 7:
      code = tiles[(short)(nTileIndex - 1)].riverSpriteCode;
      if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 ||
          code == 0x23 || code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
        return 0x17;
      }
      if (CheckTileVariantCodeMembershipSetB(nTileIndex - 1) == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x17;
      }
      return 0x18;
    case 8:
      return 0x19;
    case 9:
      return 0x1a;
    case 10:
      return 0x2b;
    case 0xb:
      if (iTileIndex % 0x6c != 0x6b) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return 0x2d - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
      }
      if (CheckTileVariantCodeMembershipSetC(nTileIndex - 0x6b) == 0) {
        if (CheckTileVariantCodeMembershipSetD(nTileIndex - 0x6b) == 0) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x2c;
        }
        return 0x2d;
      }
      return 0x2c;
    case 0xc:
      return 0x2e;
    case 0xd:
      return 0x2f;
    case 0xe:
      if (CheckTileVariantCodeMembershipSetA(nTileIndex - 1) != 0) {
        return 0x30;
      }
      if (CheckTileVariantCodeMembershipSetB(nTileIndex - 1) == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x30;
      }
      return 0x31;
    case 0xf:
      return 0x32;
    }
  } else {
    RiverSpriteCodeStorage subtype = cur->riverSpriteCode;
    if (subtype != 0) {
      switch (subtype) {
      case 0x10:
        return 0x37;
      case 0x11:
        if (CheckTileVariantCodeMembershipSetA(nTileIndex - 1) != 0) {
          return 0x38;
        }
        if (CheckTileVariantCodeMembershipSetB(nTileIndex - 1) == 0) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x38;
        }
        return 0x39;
      case 0x12:
        result = 0x3a;
        break;
      case 0x13:
        return 0x33;
      case 0x14:
        if (iTileIndex % 0x6c != 0x6b) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return 0x35 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
        }
        if (CheckTileVariantCodeMembershipSetC(nTileIndex - 0x6b) == 0) {
          if (CheckTileVariantCodeMembershipSetD(nTileIndex - 0x6b) == 0) {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x34;
          }
          return 0x35;
        }
        return 0x34;
      case 0x15:
        return 0x36;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005112f0
bool TMapMgr::CheckTileVariantCodeMembershipSetA(StrategicTileIndex tileIndex) {
  RiverSpriteCodeStorage code = terrainStateTable[tileIndex].riverSpriteCode;
  if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 || code == 0x23 ||
      code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00511360
bool TMapMgr::CheckTileVariantCodeMembershipSetB(StrategicTileIndex tileIndex) {
  RiverSpriteCodeStorage code = terrainStateTable[tileIndex].riverSpriteCode;
  if (code == 0x10 || code == 0x20 || code == 0x12 || code == 0x22 || code == 0x14 ||
      code == 0x24 || code == 0x16 || code == 0x26 || code == 0x2d || code == 0x35) {
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005113d0
bool TMapMgr::CheckTileVariantCodeMembershipSetC(StrategicTileIndex tileIndex) {
  RiverSpriteCodeStorage code = terrainStateTable[tileIndex].riverSpriteCode;
  if (code == 0xd || code == 0x1d || code == 0x11 || code == 0x21 || code == 0x12 || code == 0x22 ||
      code == 0x17 || code == 0x27 || code == 0x30 || code == 0x38) {
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00511440
bool TMapMgr::CheckTileVariantCodeMembershipSetD(StrategicTileIndex tileIndex) {
  RiverSpriteCodeStorage code = terrainStateTable[tileIndex].riverSpriteCode;
  if (code == 0xe || code == 0x1e || code == 0x13 || code == 0x23 || code == 0x14 || code == 0x24 ||
      code == 0x18 || code == 0x28 || code == 0x31 || code == 0x39) {
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005114b0
short __stdcall ResolveRiverSpriteVariantForConnectionMask(unsigned char connectionMask,
                                                           unsigned char waterTerrain) {
  const unsigned char singleDirectionVariants[8] = {7, 0, 1, 2, 3, 4, 6, 5};
  const unsigned char pairedDirectionMasks[16] = {0x12, 0x22, 0x82, 0x42, 0x24, 0x28, 0x84, 0x88,
                                                  0x44, 0x48, 0x05, 0x09, 0x90, 0x50, 0x11, 0x21};

  if (connectionMask == 0) {
    return 0;
  }

  int index;
  if (!waterTerrain) {
    for (index = 0; index < 16; ++index) {
      if (connectionMask == pairedDirectionMasks[index]) {
        return static_cast<short>(index + 0x0b);
      }
    }
  }

  for (index = 0; index < 8; ++index) {
    if (connectionMask == static_cast<unsigned char>(1 << index)) {
      return static_cast<short>(singleDirectionVariants[index] + (waterTerrain ? 0x33 : 0x2b));
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00511610
short TMapMgr::UpdateStrategicMapTileIconVariantState(StrategicTileIndex tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  switch (static_cast<unsigned char>(tile->GetTerrainKind())) {
  case kStrategicTerrainWater: {
    short neighbors[6];
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally20);
    bool foundLandNeighbor = false;
    for (int i = 0; i < 6; ++i) {
      if (neighbors[i] != -1 &&
          terrainStateTable[neighbors[i]].GetTerrainKind() != kStrategicTerrainWater) {
        foundLandNeighbor = true;
      }
    }
    if (foundLandNeighbor) {
      tile->resourceTypeByEdge[0] = 0x13;
    }
    break;
  }
  case kStrategicTerrainPlains: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 10) {
      tile->resourceTypeByEdge[0] = 0;
      break;
    }
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 5 && tile->ownerNationTag04 < 7) {
      tile->resourceTypeByEdge[0] = 5;
      break;
    }
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x24) {
      tile->resourceTypeByEdge[0] = 0x14;
    } else {
      tile->resourceTypeByEdge[0] = 0x11;
    }
    break;
  }
  case kStrategicTerrainFarmland: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x37) {
      tile->resourceTypeByEdge[0] = 0x11;
    } else {
      tile->resourceTypeByEdge[0] = 0x12;
    }
    break;
  }
  case kStrategicTerrainForest:
    tile->resourceTypeByEdge[0] = 2;
    break;
  case kStrategicTerrainSwamp:
  case kStrategicTerrainDesert: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0xf) {
      tile->resourceTypeByEdge[0] = 6;
    }
    break;
  }
  case kStrategicTerrainHills: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0xc) {
      tile->resourceTypeByEdge[0] = 1;
      break;
    }
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x14) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0x32) {
        tile->resourceTypeByEdge[0] = 3;
      } else {
        tile->resourceTypeByEdge[0] = 4;
      }
    }
    break;
  }
  case kStrategicTerrainMountain: {
    int edgeIndex = 0;
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x14) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0x32) {
        tile->resourceTypeByEdge[0] = 3;
      } else {
        tile->resourceTypeByEdge[0] = 4;
      }
      edgeIndex = 1;
    }
    if (tile->ownerNationTag04 < 7) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0xf) {
        tile->resourceTypeByEdge[edgeIndex] = 0x16;
      }
    } else {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0xa) {
        tile->resourceTypeByEdge[edgeIndex] = 0x15;
      } else {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
        if (roll % 100 < 0xf) {
          tile->resourceTypeByEdge[edgeIndex] = 0x16;
        }
      }
    }
    break;
  }
  }
  short code = ResolveRegionTileSubtypeCodeForTileIndex(tileIndex);
  tile->gateFlag = static_cast<signed char>(code);
  return code;
}

namespace {

// Shared body for GuaranteeResources' resourceType-3 and resourceType-4 passes: both are
// behaviorally identical (the original's
// resourceType-4 pass has an extra early-exit goto around the tail cleanup, but every branch
// still performs that exact same cleanup before reaching it, so unifying the two produces
// identical observable state).
void EnsureRegionHasResourceTypeAssignment(TMapMgr* mapMgr, StrategicTileIndex* linkedTileIndices,
                                           int linkedRegionTotal, signed char resourceType) {
  int foundIndex = -1;
  for (int i = 0; i < linkedRegionTotal; ++i) {
    signed char gateFlag = mapMgr->terrainStateTable[linkedTileIndices[i]].gateFlag;
    if ((gateFlag == 9 || gateFlag == 8) &&
        mapMgr->terrainStateTable[linkedTileIndices[i]].resourceTypeByEdge[0] == -1) {
      foundIndex = i;
      break;
    }
  }

  int targetIndex;
  if (foundIndex != -1) {
    targetIndex = foundIndex;
    mapMgr->terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] = resourceType;
  } else {
    signed char gateFlag;
    do {
      do {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        targetIndex =
            static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % linkedRegionTotal);
        gateFlag = mapMgr->terrainStateTable[linkedTileIndices[targetIndex]].gateFlag;
      } while (gateFlag == 8);
    } while (gateFlag == 9);
    mapMgr->terrainStateTable[linkedTileIndices[targetIndex]].gateFlag = 8;
    mapMgr->terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] = resourceType;
  }

  short targetRegion = linkedTileIndices[targetIndex];
  mapMgr->terrainStateTable[targetRegion].resourceTypeByEdge[1] = -1;
  mapMgr->terrainStateTable[targetRegion].gateFlag =
      static_cast<signed char>(mapMgr->ResolveRegionTileSubtypeCodeForTileIndex(targetRegion));
}

} // namespace

// FUNCTION: IMPERIALISM 0x00511a70
void TMapMgr::GuaranteeResources() {
  for (int nationTag = 0; nationTag <= 6; ++nationTag) {
    int i;
    int linkedRegionTotal = 0;
    for (i = 0; i < 0x180; ++i) {
      if (cityScoreTable[i].ownerNationCode00 == nationTag) {
        linkedRegionTotal += cityScoreTable[i].linkedRegionCount;
      }
    }

    StrategicTileIndex* linkedTileIndices = new StrategicTileIndex[linkedRegionTotal];
    short* cursor = linkedTileIndices;
    for (i = 0; i < 0x180; ++i) {
      if (cityScoreTable[i].ownerNationCode00 == nationTag) {
        for (int j = 0; j < cityScoreTable[i].linkedRegionCount; ++j) {
          *cursor = cityScoreTable[i].linkedTileIndices42[j];
          ++cursor;
        }
      }
    }

    short resourceTally[24] = {0};
    for (i = 0; i < linkedRegionTotal; ++i) {
      TTerrainStateRecordView* region = &terrainStateTable[linkedTileIndices[i]];
      for (int edge = 0; edge < 2; ++edge) {
        signed char resourceType = region->resourceTypeByEdge[edge];
        if (resourceType != -1) {
          ++resourceTally[resourceType];
        }
      }
    }

    if (resourceTally[3] == 0) {
      EnsureRegionHasResourceTypeAssignment(this, linkedTileIndices, linkedRegionTotal, 3);
    }
    if (resourceTally[4] == 0) {
      EnsureRegionHasResourceTypeAssignment(this, linkedTileIndices, linkedRegionTotal, 4);
    }

    delete[] linkedTileIndices;
  }
}

// FUNCTION: IMPERIALISM 0x00511e80
void TMapMgr::TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress() {
  if (field8 == 0) {
    hexNeighborWrapHorizontally20 = 1;
    BuildOrLoadGlobalMapStateForSession("mapdata", nullptr);
  }
  if (strategicMapPalettePreviewReady04 == 0) {
    g_pUiRuntimeContext->RenderTurnEventPalettePreviewSurfaceAndProgress();
  }
}

// FUNCTION: IMPERIALISM 0x00511ed0
void TMapMgr::DispatchTurnEvent7DDForActiveNation() {
  TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress();
  short nationId = g_pSimMgr->GetActiveNationId();
  g_pUiRuntimeContext->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventStrategicMap), nationId);
}

// FUNCTION: IMPERIALISM 0x00511f10
int TMapMgr::ComputeRepresentativeTileIndexForNation(int nationSlot) {
  return ComputeRepresentativeTileIndexForNationWithWrapBias(static_cast<short>(nationSlot), 1);
}

namespace {
void MarkOwnedRegionClasses(TLongintList* regionList, bool* regionClassSeen) {
  int ordinal = 1;
  int count = regionList->GetSize();
  while (ordinal <= count) {
    int regionId = regionList->At(ordinal);
    regionClassSeen[g_pGlobalMapState->cityScoreTable[regionId].regionClassA3] = true;
    ++ordinal;
    count = regionList->GetSize();
  }
}

bool AnyOwnedRegionClassSeen(TLongintList* regionList, const bool* regionClassSeen) {
  int ordinal = 1;
  int count = regionList->GetSize();
  while (ordinal <= count) {
    int regionId = regionList->At(ordinal);
    if (regionClassSeen[g_pGlobalMapState->cityScoreTable[regionId].regionClassA3]) {
      return true;
    }
    ++ordinal;
    count = regionList->GetSize();
  }
  return false;
}
} // namespace

// FUNCTION: IMPERIALISM 0x00511f30
bool TMapMgr::TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(short nationA,
                                                                          short nationB) {
  bool regionClassSeen[24] = {false};

  int i;
  MarkOwnedRegionClasses(g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList, regionClassSeen);
  for (i = 0; i < 16; ++i) {
    TMinor* minor = g_apNationAuxRuntimeStateSlots[i];
    if (minor != 0 && minor->IsEncodedNationSlotMinus200Equal(nationA) &&
        minor->ownedRegionList->GetSize() >= 1) {
      MarkOwnedRegionClasses(g_apMinorNationCapabilityObjects[i]->ownedRegionList, regionClassSeen);
    }
  }

  if (g_apTerrainTypeDescriptorTable[nationB]->ownedRegionList->GetSize() >= 1 &&
      AnyOwnedRegionClassSeen(g_apTerrainTypeDescriptorTable[nationB]->ownedRegionList,
                              regionClassSeen)) {
    return true;
  }
  for (i = 0; i < 16; ++i) {
    TMinor* minor = g_apNationAuxRuntimeStateSlots[i];
    if (minor != 0 && minor->IsEncodedNationSlotMinus200Equal(nationB) &&
        minor->ownedRegionList->GetSize() >= 1 &&
        AnyOwnedRegionClassSeen(g_apMinorNationCapabilityObjects[i]->ownedRegionList,
                                regionClassSeen)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005121d0
bool TMapMgr::IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(ProvinceIndex cityRecordIndex,
                                                                   short nationTag) {
  bool linkFound = false;
  for (int i = 0; i < cityScoreTable[cityRecordIndex].adjacentRegionCount08; ++i) {
    short adjacentRegion = cityScoreTable[cityRecordIndex].adjacentRegionIds0A[i];
    if (cityScoreTable[adjacentRegion].ownerNationCode00 == nationTag) {
      linkFound = true;
      break;
    }
  }
  if (linkFound) {
    return false;
  }

  int secondDegreeLinks[12];
  if (CollectSecondDegreeLinksMatchingNodeType(cityRecordIndex, nationTag, secondDegreeLinks) !=
      0) {
    return false;
  }
  return g_pActiveMapOrderContext->FindMapActionContextContainingNodeByIndex(cityRecordIndex) ==
         nullptr;
}

// FUNCTION: IMPERIALISM 0x005122b0
int TMapMgr::IsShiftKeyDown() {
  return GetAsyncKeyState(VK_SHIFT) & 0x8000;
}

// FUNCTION: IMPERIALISM 0x005122d0
int TMapMgr::IsAltKeyDown() {
  return GetAsyncKeyState(VK_MENU) & 0x8000;
}

// FUNCTION: IMPERIALISM 0x005123e0
int ComputeStridedRecordAddress6C(int recordBase, int recordIndex) {
  return recordBase + recordIndex * 0x6c;
}

// FUNCTION: IMPERIALISM 0x005125a0
void SplitTileIndexToRowAndColumn(StrategicTileIndex tileIndex, short* outRow, short* outCol) {
  *outRow = tileIndex / 0x6c;
  *outCol = tileIndex % 0x6c;
}

// FUNCTION: IMPERIALISM 0x005127e0
void SplitTileIndexToHexRasterColumnX2AndRow(StrategicTileIndex tileIndex, short* outColX2,
                                             unsigned short* outRow) {
  short row = tileIndex / 0x6c;
  *outColX2 = static_cast<short>(row % 2 + (tileIndex % 0x6c) * 2);
  *outRow = row;
}

// Combines a doubled hex-raster column (columnX2, as produced by
// SplitTileIndexToHexRasterColumnX2AndRow) and a row back into a linear tile index.
// FUNCTION: IMPERIALISM 0x00512850
int ComputeTileIndexFromHexColumnX2AndRow(int columnX2, int row) {
  return columnX2 / 2 + row * 0x6c;
}

// Row delta (in tiles) for one of the six hex-neighbour directions, wrapping the direction
// index into [0,6). Column deltas live in the sibling table g_Build_Hex_Area_LookupTable_00696E70.
// FUNCTION: IMPERIALISM 0x005128f0
short LookupHexNeighborRowDeltaByDirection(short direction) {
  if (direction < 0) {
    return g_Build_Hex_Area_LookupTable_00696E80[static_cast<short>(direction + 6)];
  }
  if (direction > 5) {
    direction = static_cast<short>(direction - 6);
  }
  return g_Build_Hex_Area_LookupTable_00696E80[direction];
}

// FUNCTION: IMPERIALISM 0x00512930
extern "C" StrategicTileIndex* __cdecl BuildHexAreaTileIndexList(StrategicTileIndex centerTileIndex,
                                                                 short radius) {
  short* buffer = new short[static_cast<short>(radius * 6)];
  if (buffer == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0xb85);
  }

  int row = static_cast<int>(centerTileIndex) / 0x6c;
  int rowParity = row & 1;
  int colBase = (static_cast<int>(centerTileIndex) % 0x6c) * 2;

  short* out = buffer;
  for (short direction = 0; direction < 6; ++direction) {
    int dir = static_cast<int>(direction);
    if (dir < 0) {
      dir += 6;
    } else if (dir > 5) {
      dir -= 6;
    }
    int colAccum = g_Build_Hex_Area_LookupTable_00696E70[dir] * radius + rowParity + colBase;

    dir = static_cast<int>(direction);
    if (dir < 0) {
      dir += 6;
    } else if (dir > 5) {
      dir -= 6;
    }
    int rowAccum = g_Build_Hex_Area_LookupTable_00696E80[dir] * radius + row;

    int colHalfSign = colAccum >> 0x1f;
    *out = static_cast<short>(((colAccum - colHalfSign) >> 1) + rowAccum * 0x6c);
    ++out;

    int innerDir = static_cast<int>(direction) + 2;
    if (innerDir > 5) {
      innerDir -= 6;
    }
    for (short step = 0; step < radius - 1; ++step) {
      colAccum += g_Build_Hex_Area_LookupTable_00696E70[innerDir];
      rowAccum += g_Build_Hex_Area_LookupTable_00696E80[innerDir];
      colHalfSign = colAccum >> 0x1f;
      *out = static_cast<short>(((colAccum - colHalfSign) >> 1) + rowAccum * 0x6c);
      ++out;
    }
  }
  return buffer;
}

// FUNCTION: IMPERIALISM 0x00512b50
void TMapMgr::GetNeighborTileIDArray(StrategicTileIndex tileIndex,
                                     StrategicTileIndex* neighborTiles,
                                     unsigned char wrapHorizontally) {
  unsigned int row = static_cast<unsigned int>(tileIndex / 0x6c);
  int col = tileIndex % 0x6c;
  unsigned int rowParity = row & 1U;
  short sVar4;
  if (rowParity == 0) {
    sVar4 = static_cast<short>(tileIndex + -0x6d);
    neighborTiles[kStrategicHexDirectionSouthEast] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[kStrategicHexDirectionNorthEast] = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[kStrategicHexDirectionSouthWest] = static_cast<short>(tileIndex + 0x6b);
    neighborTiles[kStrategicHexDirectionEast] = static_cast<short>(tileIndex + 1);
    neighborTiles[kStrategicHexDirectionWest] = static_cast<short>(tileIndex + -1);
  } else {
    sVar4 = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[kStrategicHexDirectionSouthEast] = static_cast<short>(tileIndex + 0x6d);
    neighborTiles[kStrategicHexDirectionNorthEast] = static_cast<short>(tileIndex + -0x6b);
    neighborTiles[kStrategicHexDirectionSouthWest] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[kStrategicHexDirectionEast] = static_cast<short>(tileIndex + 1);
    neighborTiles[kStrategicHexDirectionWest] = static_cast<short>(tileIndex + -1);
  }
  neighborTiles[kStrategicHexDirectionNorthWest] = sVar4;
  if (col < 0x6b) {
    if (col == 0) {
      if (wrapHorizontally == '\0') {
        neighborTiles[kStrategicHexDirectionWest] = static_cast<short>(tileIndex + 0x6b);
        if (rowParity == 0) {
          neighborTiles[kStrategicHexDirectionNorthWest] = static_cast<short>(tileIndex + -1);
          neighborTiles[kStrategicHexDirectionSouthWest] = static_cast<short>(tileIndex + 0xd7);
        }
      } else {
        neighborTiles[kStrategicHexDirectionWest] = -1;
        neighborTiles[kStrategicHexDirectionSouthWest] = -1;
        neighborTiles[kStrategicHexDirectionNorthWest] = -1;
      }
    }
  } else if (wrapHorizontally == '\0') {
    neighborTiles[kStrategicHexDirectionEast] = static_cast<short>(tileIndex + -0x6b);
    if (rowParity != 0) {
      neighborTiles[kStrategicHexDirectionSouthEast] = static_cast<short>(tileIndex + 1);
      neighborTiles[kStrategicHexDirectionNorthEast] = static_cast<short>(tileIndex + -0xd7);
    }
  } else {
    neighborTiles[kStrategicHexDirectionEast] = -1;
    neighborTiles[kStrategicHexDirectionNorthEast] = -1;
    neighborTiles[kStrategicHexDirectionSouthEast] = -1;
  }
  if (0x3a < static_cast<int>(row)) {
    neighborTiles[kStrategicHexDirectionSouthEast] = -1;
    neighborTiles[kStrategicHexDirectionSouthWest] = -1;
    return;
  }
  if (row == 0) {
    neighborTiles[kStrategicHexDirectionNorthEast] = -1;
    neighborTiles[kStrategicHexDirectionNorthWest] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x00512cc0
StrategicTileIndex TMapMgr::GetNeighborTileID(StrategicTileIndex tileIndex,
                                              StrategicHexDirectionStorage direction) {
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
    dir = static_cast<short>(direction) + 6;
  } else if (static_cast<short>(direction) > 5) {
    dir = static_cast<short>(direction) - 6;
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

// FUNCTION: IMPERIALISM 0x00512dd0
StrategicHexDirectionStorage TMapMgr::GetDirectionFrom(StrategicTileIndex sourceTile,
                                                       StrategicTileIndex destTile) {
  short rowFrom = sourceTile / 0x6c;
  short colFrom = sourceTile % 0x6c;
  short diagFrom = (rowFrom & 1) + colFrom * 2;
  short rowTo = destTile / 0x6c;
  short colTo = destTile % 0x6c;
  short diagTo = (rowTo & 1) + colTo * 2;

  if ((diagFrom < diagTo) && (diagTo < diagFrom + 0xd7)) {
    if (rowTo <= rowFrom) {
      return EncodeStrategicHexDirection(rowFrom <= rowTo ? kStrategicHexDirectionEast
                                                          : kStrategicHexDirectionNorthEast);
    }
    return EncodeStrategicHexDirection(kStrategicHexDirectionSouthEast);
  }
  if (((diagFrom <= diagTo) || (diagTo + 0xd7 <= diagFrom)) && (diagTo < diagFrom + 0xd7)) {
    return EncodeStrategicHexDirection(rowTo <= rowFrom ? kStrategicHexDirectionNorthWest
                                                        : kStrategicHexDirectionSouthWest);
  }
  if (rowTo <= rowFrom) {
    return EncodeStrategicHexDirection(rowTo < rowFrom ? kStrategicHexDirectionNorthWest
                                                       : kStrategicHexDirectionWest);
  }
  return EncodeStrategicHexDirection(kStrategicHexDirectionSouthWest);
}

// FUNCTION: IMPERIALISM 0x00513050
void NormalizeWrappedMapCoord108x60(short* xCoord, short* yCoord) {
  short x = *xCoord;
  if (x >= 108) {
    x = x - 108;
  } else {
    if (x >= 0)
      goto clampY;
    x = x + 108;
  }
  *xCoord = x;
clampY:
  if (*yCoord < 0) {
    *yCoord = 0;
    return;
  }
  if (*yCoord > 59)
    *yCoord = 59;
}

// FUNCTION: IMPERIALISM 0x00513120
void NormalizeWrappedMapCoord217x60(short* xCoord, short* yCoord) {
  short x = *xCoord;
  if (x > 215) {
    x = x - 217;
  } else {
    if (x >= 0)
      goto clampY;
    x = x + 216;
  }
  *xCoord = x;
clampY:
  if (*yCoord < 0) {
    *yCoord = 0;
    return;
  }
  if (*yCoord > 59)
    *yCoord = 59;
}

// FUNCTION: IMPERIALISM 0x00513170
TTown* TMapMgr::FindTownMarkerForTileByOwnerNation(StrategicTileIndex tileIndex) {
  TGreatPower* owner = g_apNationStates[terrainStateTable[tileIndex].ownerNationTag04];
  if (owner == nullptr) {
    return nullptr;
  }
  TSortedList* townMarkerList = owner->townMarkerList;
  for (int ordinal = 1; ordinal <= townMarkerList->GetCount(); ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->tileIndex14 == tileIndex) {
      return town;
    }
  }
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00513200
int TMapMgr::SetTileTransportFlags(StrategicTileIndex nTileIndex,
                                   unsigned short wTileTransportFlags) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  if (((tile->activeFlags1c & 4) != 0) && ((wTileTransportFlags & 4) == 0)) {
    g_pActiveMapOrderContext->RemovePortZoneByTile(nTileIndex);
  }
  tile->activeFlags1c = wTileTransportFlags;
  if ((wTileTransportFlags & 4) != 0) {
    g_pActiveMapOrderContext->EnsurePortZoneForTile(nTileIndex);
  }
  if ((wTileTransportFlags & 3) != 0) {
    tile->activeFlags1c |= 0x20;
  }
  return reinterpret_cast<int>(&tile->activeFlags1c);
}

const int kGlobalMapTileCount = 0x1950;

// FUNCTION: IMPERIALISM 0x00513290
void TMapMgr::DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
    ProvinceIndexStorage cityRecordIndex, int newNationTag) {
  Province* city = &cityScoreTable[cityRecordIndex];
  signed char oldNationCode = city->ownerNationCode00;

  for (int i = 0; i < city->linkedRegionCount; ++i) {
    SetTileOwnerAndInvalidateNeighborState(city->linkedTileIndices42[i],
                                           static_cast<short>(newNationTag));
  }

  city->ownerNationCode00 = static_cast<signed char>(newNationTag);
  g_apTerrainTypeDescriptorTable[oldNationCode]->RemoveRegionIdFromNationOwnedRegionList(
      cityRecordIndex);
  g_apTerrainTypeDescriptorTable[newNationTag]->AddRegionIdToNationOwnedRegionList(cityRecordIndex);
  g_pMapContextActionManager->perTileOwnerNationCodeCache1c[cityRecordIndex] =
      static_cast<short>(newNationTag);

  bool isPrimary = g_pDiplomacyTurnStateManager->IsMajorNationSlot(newNationTag) != 0;
  if (isPrimary && g_pSimMgr->multiplayerSessionRole != 2) {
    g_apNationStates[newNationTag]->NotifyActionSlot94(oldNationCode, 0x135);
  }
  if (g_pSimMgr->multiplayerSessionRole == 1) {
    g_pGameFlowState->CreateAndSendTurnEvent12_TwoShorts(static_cast<short>(newNationTag),
                                                         static_cast<short>(newNationTag));
  }
}

// FUNCTION: IMPERIALISM 0x005133f0
void TMapMgr::SetTileOwnerAndInvalidateNeighborState(short regionId, short newNationTag) {
  signed char oldOwner = terrainStateTable[regionId].ownerNationTag04;
  if (oldOwner == newNationTag) {
    return;
  }

  terrainStateTable[regionId].ownerNationTag04 = static_cast<signed char>(newNationTag);
  terrainStateTable[regionId].ownerBorderMask07 = 0;
  UpdateTileNeighborBorderInfluenceCounters(regionId, 2);

  short neighbors[6];
  GetNeighborTileIDArray(regionId, neighbors, hexNeighborWrapHorizontally20);
  for (int d = 0; d < 6; ++d) {
    if (neighbors[d] != -1) {
      terrainStateTable[neighbors[d]].ownerBorderMask07 = 0;
      UpdateTileNeighborBorderInfluenceCounters(neighbors[d], 2);
    }
  }

  if ((terrainStateTable[regionId].activeFlags1c & 0x14) && oldOwner < 7) {
    TSortedList* oldTownList = g_apNationStates[oldOwner]->townMarkerList;
    int ordinal = 1;
    int count = oldTownList->GetCount();
    TTown* matchedTown = nullptr;
    bool found = false;
    while (ordinal <= count) {
      matchedTown = static_cast<TTown*>(oldTownList->GetEntryByOrdinal(ordinal));
      if (matchedTown->tileIndex14 == regionId) {
        found = true;
        break;
      }
      ++ordinal;
      count = oldTownList->GetCount();
    }
    if (found) {
      oldTownList->RemoveAtOrdinal(ordinal);
      matchedTown->ownerNation1c = newNationTag;
      g_apNationStates[newNationTag]->townMarkerList->AddTail(matchedTown);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005135a0
byte TMapMgr::FindResourceCapabilityRequirementLevelByType(StrategicTileIndex tileIndex,
                                                           char resourceType) {
  for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
    if (terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex] == resourceType) {
      return FindResourceCapabilityRequirementLevel(tileIndex, static_cast<short>(edgeIndex));
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00513610
byte TMapMgr::FindResourceCapabilityRequirementLevel(StrategicTileIndex tileIndex,
                                                     short edgeIndex) {
  signed char resourceType = terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex];
  signed char raw = terrainStateTable[tileIndex].developmentClassNibbles0c;
  signed char index = g_abResourceTypeUsesHighNibbleFlag[resourceType] != 0 ? (raw >> 4) : raw;
  return g_abUniversityRequirementLevelById[resourceType][index];
}

// FUNCTION: IMPERIALISM 0x00513660
byte TMapMgr::GetTileCivilianWorkOrderCostClassNibble(StrategicTileIndex nTileIndex,
                                                      char fUseHighNibble) {
  if (fUseHighNibble) {
    return terrainStateTable[nTileIndex].developmentClassNibbles0c >> 4;
  }
  return terrainStateTable[nTileIndex].developmentClassNibbles0c & 0xf;
}

// FUNCTION: IMPERIALISM 0x005136a0
void TMapMgr::SetCivilianDevelopmentClassNibble(StrategicTileIndex tileIndex, char selectHighNibble,
                                                byte value, char param4) {
  unsigned char packed = terrainStateTable[tileIndex].developmentClassNibbles0c;
  if (selectHighNibble) {
    packed = (packed & 0xf) | (value << 4);
  } else {
    packed = (packed & 0xf0) | value;
  }
  terrainStateTable[tileIndex].developmentClassNibbles0c = packed;
  if (selectHighNibble) {
    if (static_cast<signed char>(value) > 0 && param4 != 0) {
      terrainStateTable[tileIndex].pendingDevelopmentFlag0d = 0x7f;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00513720
short TMapMgr::FindMaxResourceCapabilityValueForTile(StrategicTileIndex tileIndex,
                                                     char categoryCode, int nationSlot) {
  short maxValue = 0;
  for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
    signed char resourceType = terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex];
    if (resourceType == -1) {
      continue;
    }
    if (g_abResourceTypeCapabilityCategory[resourceType] != categoryCode) {
      continue;
    }
    short value =
        g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationSlot][resourceType];
    if (value > maxValue) {
      maxValue = value;
    }
  }
  return maxValue;
}

// FUNCTION: IMPERIALISM 0x005137b0
char TMapMgr::CanBuildPortAtTile(StrategicTileIndex tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  char result = 0;
  if (tile->GetTerrainKind() != kStrategicTerrainMountain &&
      tile->GetTerrainKind() != kStrategicTerrainHills) {
    short neighbors[6];
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally20);
    for (short direction = 0; direction < 6; ++direction) {
      short neighbor = neighbors[direction];
      if (neighbor != -1 &&
          terrainStateTable[neighbor].GetTerrainKind() == kStrategicTerrainWater) {
        result = 1;
        break;
      }
    }
  }
  if (result == 0 && tile->riverSpriteCode != kRiverSpriteCodeNone &&
      EvaluateTerrainFlowCrossNationBoundaryToSea(tileIndex) == 0) {
    result = 1;
  }
  return result;
}
// sea tile reachable without crossing into another nation's territory. Not (region class
// 2 or 3): scans the 6 hex neighbors for an unclaimed (tileActionState16 == -1) sea tile
// (water terrain) none of whose own 6 neighbors belong to a different, non-unclaimed
// nation (ownerNationTag04 < 0x17 and != this tile's own owner). Falls back to
// EvaluateTerrainFlowCrossNationBoundaryToSea when no such neighbor exists but this tile
// has a road/feature flow code.
// FUNCTION: IMPERIALISM 0x00513980
bool TMapMgr::IsValidSecondaryNationHomeTileCandidate(StrategicTileIndex tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  StrategicTerrainKind terrainKind = tile->GetTerrainKind();
  short homeNation = tile->ownerNationTag04;
  bool isValid = false;

  if (terrainKind != kStrategicTerrainMountain && terrainKind != kStrategicTerrainHills) {
    short row = static_cast<short>(tileIndex / 0x6c);
    short colX2 = static_cast<short>(row % 2 + (tileIndex % 0x6c) * 2);

    for (short direction = 0; direction < 6; ++direction) {
      short wrappedDir = direction;
      if (wrappedDir < 0) {
        wrappedDir = static_cast<short>(wrappedDir + 6);
      } else if (wrappedDir > 5) {
        wrappedDir = static_cast<short>(wrappedDir - 6);
      }
      short candColX2 =
          static_cast<short>(colX2 + g_Build_Hex_Area_LookupTable_00696E70[wrappedDir]);
      short candRow = static_cast<short>(row + LookupHexNeighborRowDeltaByDirection(direction));
      NormalizeWrappedMapCoord217x60(&candColX2, &candRow);
      StrategicTileIndex candidateTile =
          static_cast<short>(ComputeTileIndexFromHexColumnX2AndRow(candColX2, candRow));
      if (candidateTile < 0 || candidateTile >= 0x1950) {
        candidateTile = -1;
      }

      if (candidateTile != -1 &&
          terrainStateTable[candidateTile].GetTerrainKind() == kStrategicTerrainWater) {
        isValid = true;
        short seaRow = static_cast<short>(candidateTile / 0x6c);
        short seaColX2 = static_cast<short>(seaRow % 2 + (candidateTile % 0x6c) * 2);

        for (short innerDir = 0; innerDir < 6; ++innerDir) {
          short innerWrappedDir = innerDir;
          if (innerWrappedDir < 0) {
            innerWrappedDir = static_cast<short>(innerWrappedDir + 6);
          } else if (innerWrappedDir > 5) {
            innerWrappedDir = static_cast<short>(innerWrappedDir - 6);
          }
          short nColX2 =
              static_cast<short>(seaColX2 + g_Build_Hex_Area_LookupTable_00696E70[innerWrappedDir]);
          short nRow = static_cast<short>(seaRow + LookupHexNeighborRowDeltaByDirection(innerDir));
          NormalizeWrappedMapCoord217x60(&nColX2, &nRow);
          StrategicTileIndex neighborTile =
              static_cast<short>(ComputeTileIndexFromHexColumnX2AndRow(nColX2, nRow));
          if (neighborTile < 0 || neighborTile >= 0x1950) {
            neighborTile = -1;
          }
          if (neighborTile != -1) {
            short neighborNation = terrainStateTable[neighborTile].ownerNationTag04;
            if (neighborNation < 0x17 && neighborNation != homeNation) {
              isValid = false;
              break;
            }
          }
        }

        if (terrainStateTable[candidateTile].tileActionState16 != kMapTileActionStateNone) {
          isValid = false;
        }
        if (isValid) {
          break;
        }
      }
    }
  }

  if (!isValid && tile->riverSpriteCode != kRiverSpriteCodeNone &&
      EvaluateTerrainFlowCrossNationBoundaryToSea(tileIndex) == 0) {
    isValid = true;
  }
  return isValid;
}

// Whether `tileIndex` can reach a sea tile — directly via one of its six hex
// neighbours, or (when no sea neighbour exists) via its terrain-flow chain —
// whose owning nation is NOT diplomatically related to the tile's own nation
// through the active type-3/4 order mask. Every original callsite loads ECX
// from g_pGlobalMapState (0x6a43d4): a real TMapMgr method, not the free
// __cdecl(short) the old TTown typedef-cast pretended (it dropped `this`).
// The hex wrap/clamp arithmetic is open-coded here because the original body
// inlines it (no calls to the 0x5128f0/0x512850 helpers at this site).
// FUNCTION: IMPERIALISM 0x00513ca0
char TMapMgr::HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(StrategicTileIndex tileIndex) {
  int originNation = static_cast<signed char>(terrainStateTable[tileIndex].ownerNationTag04);
  char result = 0;
  short row = static_cast<short>(tileIndex / 0x6c);
  int colX2 = row % 2 + (tileIndex % 0x6c) * 2;

  for (short direction = 0; direction <= 5; ++direction) {
    short colDir = direction;
    if (colDir < 0) {
      colDir = static_cast<short>(colDir + 6);
    } else if (colDir > 5) {
      colDir = static_cast<short>(colDir - 6);
    }
    short candColX2 = static_cast<short>(colX2 + g_Build_Hex_Area_LookupTable_00696E70[colDir]);
    short rowDir = direction;
    if (rowDir < 0) {
      rowDir = static_cast<short>(rowDir + 6);
    } else if (rowDir > 5) {
      rowDir = static_cast<short>(rowDir - 6);
    }
    short candRow = static_cast<short>(row + g_Build_Hex_Area_LookupTable_00696E80[rowDir]);

    if (candColX2 > 0xd7) {
      candColX2 = static_cast<short>(candColX2 - 0xd9);
    } else if (candColX2 < 0) {
      candColX2 = static_cast<short>(candColX2 + 0xd8);
    }
    if (candRow < 0) {
      candRow = 0;
    } else if (candRow > 0x3b) {
      candRow = 0x3b;
    }

    StrategicTileIndex neighborTile = static_cast<short>(candColX2 / 2 + candRow * 0x6c);
    if (neighborTile < 0 || neighborTile >= 0x1950) {
      neighborTile = -1;
    }
    if (neighborTile != -1 &&
        terrainStateTable[neighborTile].GetTerrainKind() == kStrategicTerrainWater) {
      short neighborNation = terrainStateTable[neighborTile].ownerNationTag04;
      if (g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(neighborNation)
              ->HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask(originNation) == 0) {
        result = 1;
      }
      break;
    }
  }

  if (result == 0 &&
      g_pGlobalMapState->terrainStateTable[tileIndex].riverSpriteCode != kRiverSpriteCodeNone &&
      EvaluateTerrainFlowCrossNationBoundaryToSea(tileIndex) == 0) {
    short seaTile = TraceTerrainFlowToNearestSeaTile(tileIndex);
    short seaNation = terrainStateTable[seaTile].ownerNationTag04;
    if (g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(seaNation)
            ->HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask(originNation) == 0) {
      result = 1;
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x00513ed0
byte TMapMgr::CheckTileProspectingDiscoveryCandidate(StrategicTileIndex nTileIndex) {
  byte fHasDiscoveryCandidate;
  int nResourceSlotIndex;
  char cTileResourceCode;

  fHasDiscoveryCandidate = 0;
  if (terrainStateTable[nTileIndex].resourceTypeByEdge[0] != '\0') {
    nResourceSlotIndex = 0;
    do {
      if (fHasDiscoveryCandidate != 0) {
        return fHasDiscoveryCandidate;
      }
      cTileResourceCode =
          terrainStateTable[nTileIndex].resourceTypeByEdge[(short)nResourceSlotIndex];
      if ((((cTileResourceCode == '\x03') || (cTileResourceCode == '\x04')) ||
           (cTileResourceCode == '\x15')) ||
          ((cTileResourceCode == '\x16') ||
           ((cTileResourceCode == '\x06') &&
            (g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] !=
             '\0')))) {
        fHasDiscoveryCandidate = 1;
      }
      nResourceSlotIndex = nResourceSlotIndex + 1;
    } while (nResourceSlotIndex < 2);
  }
  return fHasDiscoveryCandidate;
}

// FUNCTION: IMPERIALISM 0x00513f60
void TMapMgr::SetHexAdjacencyDirectionFlagsForTilePair(StrategicTileIndex sourceTile,
                                                       StrategicTileIndex destTile,
                                                       int unusedParam3) {
  (void)unusedParam3;
  short direction = GetDirectionFrom(sourceTile, destTile);
  terrainStateTable[sourceTile].adjacencyBits06 |=
      static_cast<unsigned char>(g_hexDirectionBitMasksAlt_00696ea8[direction]);
  short oppositeDirection = (direction + 3) % 6;
  terrainStateTable[destTile].adjacencyBits06 |=
      static_cast<unsigned char>(g_hexDirectionBitMasksAlt_00696ea8[oppositeDirection]);
}

// FUNCTION: IMPERIALISM 0x00513ff0
void TMapMgr::ApplyRailSectionEndpointDirectionFlags(StrategicTileIndex sourceTile,
                                                     StrategicTileIndex destTile,
                                                     short ownerNation) {
  (void)ownerNation;
  short dir = GetDirectionFrom(sourceTile, destTile);
  terrainStateTable[sourceTile].railFlags17 += kHexDirectionBitMask[dir];
  terrainStateTable[destTile].railFlags17 += kHexDirectionBitMask[(dir + 3) % 6];
}

// Rescind counterpart to ApplyRailSectionEndpointDirectionFlags above: same bit-flag table,
// subtracts instead of adding -- matches HandleCivilianReportDecision's "rescind a rail
// section" refund path.
// FUNCTION: IMPERIALISM 0x00514080
void TMapMgr::ApplyEngineerRailCostDeltaForConnectedTiles(StrategicTileIndex tileA,
                                                          StrategicTileIndex tileB,
                                                          short ownerNation) {
  (void)ownerNation;
  short dir = GetDirectionFrom(tileA, tileB);
  terrainStateTable[tileA].railFlags17 -= kHexDirectionBitMask[dir];
  terrainStateTable[tileB].railFlags17 -= kHexDirectionBitMask[(dir + 3) % 6];
}

// FUNCTION: IMPERIALISM 0x00514110
short TMapMgr::ResolveRegionTileSubtypeCodeForTileIndex(StrategicTileIndex tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  switch (static_cast<unsigned char>(tile->GetTerrainKind())) {
  case kStrategicTerrainPlains:
    if (tile->resourceTypeByEdge[0] == 0) {
      return 2;
    }
    if (tile->resourceTypeByEdge[0] == 5) {
      return 4;
    }
    if (tile->resourceTypeByEdge[0] == 0x14) {
      return 3;
    }
    return (tile->activeFlags1c & 2) ? 0xe : 1;
  case kStrategicTerrainForest:
    if (tile->gateFlag == -1) {
      return 0xd;
    }
    return tile->gateFlag;
  case kStrategicTerrainHills:
    return (tile->resourceTypeByEdge[0] != 1) + 7;
  case kStrategicTerrainMountain:
    return 9;
  case kStrategicTerrainSwamp:
    return 0xa;
  case kStrategicTerrainDesert:
    if (tile->gateFlag != -1) {
      return tile->gateFlag;
    } else {
      short quotient = tileIndex / 0x6c;
      if (quotient < 0xf) {
        return 0xc;
      }
      if (quotient > 0x2d) {
        return 0xc;
      }
      return 0xb;
    }
  case kStrategicTerrainFarmland:
    return (tile->resourceTypeByEdge[0] != 0x11) + 5;
  default:
    return 0;
  }
}

// FUNCTION: IMPERIALISM 0x00514250
TCivUnit* TMapMgr::GetTileUnitEntryByOwner(StrategicTileIndex tileIndex, short nationId) {
  TCivUnit* entry = GetFirstCivilianOrderOnTile(tileIndex);
  while ((entry != nullptr) && (entry->field_18 != nationId)) {
    entry = static_cast<TCivUnit*>(entry->nextOnTile);
  }
  return entry;
}

// Whether `tileIndex` (a candidate home tile for a secondary/minor nation) has a nearby

// FUNCTION: IMPERIALISM 0x00514290
short TMapMgr::ResolveTileOwnerNationCodeNormalized(int tileIndex) {
  short ownerCode = cityScoreTable[tileIndex].ownerNationCode00;
  if (ownerCode == -1) {
    return ownerCode;
  }
  TCountry* nation = g_apTerrainTypeDescriptorTable[ownerCode];
  if (nation->needLevelByNation[1] < 200) {
    return ownerCode;
  }
  short code = nation->needLevelByNation[1];
  if (code < 200) {
    if (code < 100) {
      return nation->needLevelByNation[0];
    }
    return code - 100;
  }
  return code - 200;
}

// FUNCTION: IMPERIALISM 0x00514310
bool TMapMgr::HasCivilianUnitKind(StrategicTileIndex tileIndex, CivilianUnitKindStorage unitKind) {
  for (TCivUnit* order = terrainStateTable[tileIndex].firstCivilianOrder20; order != nullptr;
       order = static_cast<TCivUnit*>(order->nextOnTile)) {
    if (order->orderType == unitKind) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00514360
bool TMapMgr::HasCivilianUnitKindWithOrder(StrategicTileIndex tileIndex,
                                           CivilianUnitKindStorage unitKind,
                                           UnitOrderStorage orderValue) {
  for (TCivUnit* order = terrainStateTable[tileIndex].firstCivilianOrder20; order != nullptr;
       order = static_cast<TCivUnit*>(order->nextOnTile)) {
    if (order->orderType == unitKind && order->unitOrder == DecodeUnitOrder(orderValue)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005143d0
void TMapMgr::FloodFillTileRegionMarker(StrategicTileIndex nTileIndex, short nOwnerNationId) {
  unsigned char regionMarkerId = static_cast<unsigned char>(g_nNextRegionMarkerId);
  terrainStateTable[nTileIndex].regionSubtypeTag05 = regionMarkerId;

  if (terrainStateTable[nTileIndex].activeFlags1c & 2) {
    short cityIdx = terrainStateTable[nTileIndex].cityRecordIndex;
    if (cityScoreTable[cityIdx].lastTurnTick == 999) {
      cityScoreTable[cityIdx].lastTurnTick = g_pSimMgr->GetEconomicTurn();
    }
  }

  short neighbors[6];
  GetNeighborTileIDArray(nTileIndex, neighbors, hexNeighborWrapHorizontally20);
  for (int d = 0; d < 6; ++d) {
    StrategicTileIndex neighborTile = neighbors[d];
    if (neighborTile == -1) {
      continue;
    }
    if (terrainStateTable[neighborTile].ownerNationTag04 != nOwnerNationId) {
      continue;
    }
    if (terrainStateTable[neighborTile].regionSubtypeTag05 != -1) {
      continue;
    }

    terrainStateTable[neighborTile].regionSubtypeTag05 = regionMarkerId;
    if (terrainStateTable[neighborTile].activeFlags1c & 2) {
      short cityIdx = terrainStateTable[neighborTile].cityRecordIndex;
      bool skipRedraw = false;
      if (cityScoreTable[cityIdx].lastTurnTick == 999) {
        cityScoreTable[cityIdx].lastTurnTick = g_pSimMgr->GetEconomicTurn();
        if (g_nSaveFormatVersion == -3) {
          skipRedraw = true;
        } else if (g_pSimMgr->multiplayerSessionRole == 1) {
          g_pGameFlowState->DispatchCityRedrawInvalidateEvent(cityIdx);
        }
      }
      if (!skipRedraw && g_nSaveFormatVersion != -3 && g_pSimMgr->multiplayerSessionRole == 1) {
        DispatchTileRedrawInvalidateEvent(neighborTile);
      }
    }
  }

  g_nNextRegionMarkerId = static_cast<short>(g_nNextRegionMarkerId) + 1;
}

// FUNCTION: IMPERIALISM 0x005145b0
int TMapMgr::QueueDepotConstructionOrder(StrategicTileIndex nTileIndex, short nNationId) {
  CString emptyName(g_szEmptyString);
  TTown* town;

  if ((terrainStateTable[nTileIndex].activeFlags1c & 4) != 0) {
    town = FindTownMarkerForTileByOwnerNation(nTileIndex);
    town->activeFlag4f = true;
  } else {
    town = new TTown();
    town->InitializeTownMarker(static_cast<LPCSTR>(emptyName), nTileIndex, 0, nNationId);

    TSortedList* townMarkers = g_apNationStates[nNationId]->townMarkerList;
    if (townMarkers == 0) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMap.cpp", 0xfa8);
    }
    townMarkers->AddTail(town);
    FloodFillTileRegionMarker(nTileIndex, nNationId);
  }

  TGreatPower* nation = g_apNationStates[nNationId];
  if (nation->diplomacyEligibilityA0 == 0) {
    nation->treasuryValue10 -= 2000;
  }
  terrainStateTable[nTileIndex].activeFlags1c |= 0x10;

  if (g_nSaveFormatVersion != -3 && g_pSimMgr->multiplayerSessionRole != 0) {
    g_pGameFlowState->DispatchTurnEvent31TaggedPayload(0x746f776e, town, -2);
    g_pGameFlowState->DispatchCityRedrawInvalidateEvent(
        terrainStateTable[nTileIndex].cityRecordIndex);
    DispatchTileRedrawInvalidateEvent(nTileIndex);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005147d0
void TMapMgr::QueuePortConstructionOrder(StrategicTileIndex nTileIndex, short nNationId) {
  TTown* town;

  if ((terrainStateTable[nTileIndex].activeFlags1c & 0x10) != 0) {
    town = FindTownMarkerForTileByOwnerNation(nTileIndex);
    town->enabledFlag4d = true;
  } else {
    town = new TTown();
    town->InitializeTownMarker(g_szEmptyString, nTileIndex, 1, nNationId);

    TSortedList* townMarkers = g_apNationStates[nNationId]->townMarkerList;
    if (townMarkers == 0) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMap.cpp", 0xfda);
    }
    townMarkers->AddTail(town);
    FloodFillTileRegionMarker(nTileIndex, nNationId);
  }

  TGreatPower* nation = g_apNationStates[nNationId];
  if (nation->diplomacyEligibilityA0 == 0) {
    nation->treasuryValue10 -= 3000;
  }
  terrainStateTable[nTileIndex].activeFlags1c |= 4;
  g_pActiveMapOrderContext->EnsurePortZoneForTile(nTileIndex);

  if (g_nSaveFormatVersion != -3 && g_pSimMgr->multiplayerSessionRole != 0) {
    g_pGameFlowState->DispatchTurnEvent31TaggedPayload(0x746f776e, town, -2);
    g_pGameFlowState->DispatchCityRedrawInvalidateEvent(
        terrainStateTable[nTileIndex].cityRecordIndex);
    DispatchTileRedrawInvalidateEvent(nTileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x005149d0
void TMapMgr::SetProvinceCapitalTileFlagBit08(ProvinceIndexStorage nProvinceId) {
  short capitalTileIndex = cityScoreTable[nProvinceId].cityTileIndex04;
  terrainStateTable[capitalTileIndex].activeFlags1c |= 8;
  ++cityScoreTable[nProvinceId].fortLevel03;
}

// FUNCTION: IMPERIALISM 0x00514a20
void TMapMgr::SetTileTransportFlagsTo0x37AndRefreshNeighbors(StrategicTileIndex nTileIndex,
                                                             short nOwnerNationId) {
  short cityRecordIndex = terrainStateTable[nTileIndex].cityRecordIndex;
  SetRegionTileSubtypeAndRefreshNeighborFlags(cityRecordIndex, nTileIndex);

  terrainStateTable[nTileIndex].activeFlags1c = 0x17;
  terrainStateTable[nTileIndex].activeFlags1c |= 0x20;
  FloodFillTileRegionMarker(nTileIndex, nOwnerNationId);

  signed char originRegionTag = terrainStateTable[nTileIndex].regionSubtypeTag05;
  for (int direction = 0; direction <= 6; ++direction) {
    StrategicTileIndex neighborTile =
        (direction == 6) ? nTileIndex
                         : GetNeighborTileID(nTileIndex, static_cast<short>(direction));
    if (neighborTile == -1) {
      continue;
    }
    TTerrainStateRecordView* neighbor = &terrainStateTable[neighborTile];
    if (neighbor->regionSubtypeTag05 != originRegionTag) {
      continue;
    }

    bool eligible = false;
    for (int edge = 0; edge < 2; ++edge) {
      signed char resourceType = neighbor->resourceTypeByEdge[edge];
      if ((resourceType == 0x11 || resourceType == 0x12) &&
          g_abGateFlagQualifies[neighbor->gateFlag] != 0) {
        eligible = true;
      }
    }
    if (eligible) {
      SetCivilianDevelopmentClassNibble(neighborTile, 0, 1, 1);
    }
  }

  g_pActiveMapOrderContext->EnsurePortZoneForTile(nTileIndex);
  terrainStateTable[nTileIndex].gateFlag =
      static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(nTileIndex));
}

// FUNCTION: IMPERIALISM 0x00514c80
StrategicTileIndex
TMapMgr::FindReachableRecruitSpawnTileWithVisitedReset(StrategicTileIndex startTileIndex,
                                                       char allowActiveFlag2) {
  signed char ownerNationTag = terrainStateTable[startTileIndex].ownerNationTag04;
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  return FindReachableRecruitSpawnTileRecursive(startTileIndex, ownerNationTag, allowActiveFlag2);
}

// FUNCTION: IMPERIALISM 0x00514cd0
StrategicTileIndex TMapMgr::FindReachableRecruitSpawnTileRecursive(StrategicTileIndex tileIndex,
                                                                   short ownerNationTag,
                                                                   char allowActiveFlag2) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
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

  StrategicTileIndex neighborTiles[6];
  GetNeighborTileIDArray(tileIndex, neighborTiles, hexNeighborWrapHorizontally20);
  for (short neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    if (neighborTiles[neighborIndex] == -1) {
      continue;
    }
    StrategicTileIndex foundTile = FindReachableRecruitSpawnTileRecursive(
        neighborTiles[neighborIndex], ownerNationTag, allowActiveFlag2);
    if (foundTile != -1) {
      return foundTile;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00514dc0
void TMapMgr::SeedValidCitySiteCandidateTilesForNation(short nationTag) {
  field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    if (tile->ownerNationTag04 == nationTag && tile->GetTerrainKind() != kStrategicTerrainHills &&
        tile->GetTerrainKind() != kStrategicTerrainMountain &&
        tile->GetTerrainKind() != kStrategicTerrainSwamp) {
      tile->recruitSearchVisited0e = IsValidSecondaryNationHomeTileCandidate(tileIndex) ? 0 : 1;
    } else {
      tile->recruitSearchVisited0e = 1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00514e40
void TMapMgr::SeedRecruitSearchVisitedStateExcludingNation(short ownerNationTag) {
  this->field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e =
        (terrainStateTable[tileIndex].ownerNationTag04 != ownerNationTag) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00514e80
void TMapMgr::SeedRecruitSearchVisitedStateFromSelectedCivilianOrder(TCivUnit* unusedOrder) {
  (void)unusedOrder;
  TTerrainStateRecordView* tile = terrainStateTable;
  this->field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex, ++tile) {
    TCivUnit* selectedEntry = g_pSelectedCivilianOrderState->selectedEntry;
    if (selectedEntry == nullptr) {
      continue;
    }
    if (selectedEntry->tileIndex06 != 0) {
      tile->recruitSearchVisited0e = 1;
    } else {
      tile->recruitSearchVisited0e = (tile->activeFlags1c >> 4) & 1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00514ef0
void TMapMgr::ResetRecruitSearchVisitedState() {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  this->field9 = 0;
}

// FUNCTION: IMPERIALISM 0x00514f20
void TMapMgr::SeedRecruitSearchVisitedStateAndClearAlliedTerritory(TCivUnit* pCivilianOrderEntry) {
  short refTileIndex = pCivilianOrderEntry->tileIndex06;
  signed char refOwner = terrainStateTable[refTileIndex].ownerNationTag04;
  this->field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e =
        (terrainStateTable[tileIndex].ownerNationTag04 != refOwner) ? 1 : 0;
  }

  if (pCivilianOrderEntry->orderType != 1 && pCivilianOrderEntry->orderType != 7) {
    return;
  }
  if (pCivilianOrderEntry->field_1C != 0) {
    return;
  }

  TTerrainStateRecordView* refTile = &terrainStateTable[refTileIndex];
  unsigned char flags = refTile->activeFlags1c;
  bool gateFlagPasses = (flags & 3) != 0 && refTile->gateFlag != 0;
  if (!gateFlagPasses && (flags & 4) == 0) {
    return;
  }

  if (refOwner == pCivilianOrderEntry->field_18) {
    TTown* town = FindTownMarkerForTileByOwnerNation(refTileIndex);
    if (town->enabledFlag4d == 0) {
      return;
    }
  }

  for (int minorSlot = 7; minorSlot < 23; ++minorSlot) {
    TMinor* minorObj = g_apMinorNationCapabilityObjects[minorSlot - 7];
    if (minorObj == nullptr) {
      continue;
    }
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(minorSlot, pCivilianOrderEntry->field_18)) {
      continue;
    }
    terrainStateTable[static_cast<short>(minorObj->homeTileIndex)].recruitSearchVisited0e = 0;
  }

  TGreatPower* owner = g_apNationStates[pCivilianOrderEntry->field_18];
  TSortedList* townMarkerList = owner->townMarkerList;
  for (int ordinal = 1; ordinal <= townMarkerList->GetCount(); ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->enabledFlag4d != 0) {
      terrainStateTable[town->tileIndex14].recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005150e0
void TMapMgr::SeedRecruitSearchVisitedStateFromMilitaryUnitCandidates(
    TMilitaryUnit* const candidates[6], short orderTargetSlot) {
  int i;
  TMilitaryUnit* unit = nullptr;
  for (i = 0; i < 6; ++i) {
    if (candidates[i] != nullptr) {
      unit = candidates[i];
    }
  }
  if (unit == nullptr) {
    return;
  }

  short nationSlot = unit->field_18;
  field9 = 1;
  int tileScanIndex;
  for (tileScanIndex = 0; tileScanIndex < 0x1950; ++tileScanIndex) {
    terrainStateTable[tileScanIndex].recruitSearchVisited0e = 1;
  }
  terrainStateTable[unit->tileIndex06].recruitSearchVisited0e = 0;

  // Minimum per-candidate combat class across all 6 slots (capped at 3) -- computed but
  // never read by the original; kept for byte-fidelity rather than dropped as dead code.
  short minCombatClass = 3;
  for (i = 0; i < 6; ++i) {
    if (candidates[i] != nullptr) {
      short combatClass = g_awUnitCombatClassBySlot[candidates[i]->orderType];
      if (combatClass < minCombatClass) {
        minCombatClass = combatClass;
      }
    }
  }
  (void)minCombatClass;

  StrategicTileIndex targetTileIndex;
  if (orderTargetSlot != 0) {
    targetTileIndex = unit->orderTargetTiles28[orderTargetSlot - 1];
  } else {
    targetTileIndex = unit->tileIndex06;
  }

  for (short direction = 0; direction < 6; ++direction) {
    StrategicTileIndex neighborTile = GetNeighborTileID(targetTileIndex, direction);
    if (neighborTile == -1) {
      continue;
    }
    TTerrainStateRecordView* neighbor = &terrainStateTable[neighborTile];
    if (neighbor->ownerNationTag04 == nationSlot) {
      neighbor->recruitSearchVisited0e = 0;
    } else if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(neighbor->ownerNationTag04,
                                                               nationSlot)) {
      neighbor->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00515330
void TMapMgr::MapMgrSlot23(TCivUnit* pCivilianOrderEntry) {
  field9 = 1;
  short nationTag = pCivilianOrderEntry->field_18;
  unsigned char eligibleGateFlags[24] = {0};
  eligibleGateFlags[8] = 1;
  eligibleGateFlags[9] = 1;
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x13] == 2) {
    eligibleGateFlags[10] = 1;
    eligibleGateFlags[11] = 1;
    eligibleGateFlags[12] = 1;
  }
  unsigned char nationBit = 1 << nationTag;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      tile->recruitSearchVisited0e = 0;
      continue;
    }
    if (tile->ownerNationTag04 != nationTag) {
      if (tile->ownerNationTag04 < 7) {
        tile->recruitSearchVisited0e = 1;
        continue;
      }
      if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
              nationTag, tile->ownerNationTag04) != 2) {
        tile->recruitSearchVisited0e = 1;
        continue;
      }
    }
    if (eligibleGateFlags[tile->gateFlag] == 0) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    tile->recruitSearchVisited0e = (nationBit & tile->pendingDevelopmentFlag0d) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515460
void TMapMgr::MapMgrSlot24(TCivUnit* pCivilianOrderEntry) {
  short nationTag = pCivilianOrderEntry->field_18;
  bool recruitTierFlagIsTwo =
      (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x13] == 2);
  field9 = 1;
  unsigned char nationBit = 1 << nationTag;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    tile->recruitSearchVisited0e = 1;
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      continue;
    }
    if (tile->ownerNationTag04 < 7) {
      continue;
    }
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
            nationTag, tile->ownerNationTag04) != 2) {
      continue;
    }
    if (tile->secondaryOwnerNationTag18 != -1) {
      continue;
    }
    if (g_abGateFlagQualifies[tile->gateFlag] == 0) {
      continue;
    }
    bool found = false;
    for (int edge = 0; edge < 2; ++edge) {
      signed char resourceType = tile->resourceTypeByEdge[edge];
      if (resourceType == 0 || resourceType == 1 || resourceType == 2) {
        found = true;
        continue;
      }
      if (tile->pendingDevelopmentFlag0d & nationBit) {
        if (resourceType == 3 || resourceType == 4 || resourceType == 0x15 ||
            resourceType == 0x16) {
          found = true;
        } else if (recruitTierFlagIsTwo && resourceType == 6) {
          found = true;
        }
      }
    }
    if (found) {
      tile->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005155c0
void TMapMgr::SeedRecruitSearchVisitedStateByCapabilityThreshold(TCivUnit* pCivilianOrderEntry) {
  unsigned char qualifiesByResourceType[23] = {0};
  if (pCivilianOrderEntry->orderType == 0) {
    qualifiesByResourceType[3] = 1;
    qualifiesByResourceType[4] = 1;
    qualifiesByResourceType[21] = 1;
    qualifiesByResourceType[22] = 1;
  } else {
    qualifiesByResourceType[6] = 1;
  }

  this->field9 = 1;
  short nationTag = pCivilianOrderEntry->field_18;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->ownerNationTag04 != nationTag && tile->secondaryOwnerNationTag18 != nationTag) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->pendingDevelopmentFlag0d == 0) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    short maxValue = 0;
    for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
      signed char resourceType = tile->resourceTypeByEdge[edgeIndex];
      if (resourceType == -1) {
        continue;
      }
      if (qualifiesByResourceType[resourceType] == 0) {
        continue;
      }
      short value =
          g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationTag][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    signed char highNibble = tile->developmentClassNibbles0c >> 4;
    tile->recruitSearchVisited0e = (highNibble >= maxValue) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515720
void TMapMgr::MarkType5NeighborTilesUnavailableByNationCapability(TCivUnit* pCivilianOrderEntry) {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 1;
  }

  short nationTag = pCivilianOrderEntry->field_18;
  TGreatPower* nation = g_apNationStates[nationTag];
  TSortedList* townMarkerList = nation->townMarkerList;
  int townCount = townMarkerList->GetCount();
  for (int ordinal = 1; ordinal <= townCount; ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->enabledFlag4d == 0) {
      continue;
    }
    short regionId = town->tileIndex14;
    signed char townTag5 = terrainStateTable[regionId].regionSubtypeTag05;
    short neighbors[6];
    GetNeighborTileIDArray(regionId, neighbors, hexNeighborWrapHorizontally20);
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] == -1) {
        continue;
      }
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (neighbor->GetTerrainKind() != kStrategicTerrainWater) {
        continue;
      }
      if (neighbor->regionSubtypeTag05 != townTag5) {
        continue;
      }
      if (neighbor->developmentClassNibbles0c <
          g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationTag][19]) {
        neighbor->recruitSearchVisited0e = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00515890
void TMapMgr::SeedRecruitSearchVisitedStateByCapabilityThresholdAlt(TCivUnit* pCivilianOrderEntry) {
  this->field9 = 1;
  short nationTag = pCivilianOrderEntry->field_18;
  short orderType = pCivilianOrderEntry->orderType;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    tile->recruitSearchVisited0e = 1;
    if (tile->ownerNationTag04 != nationTag && tile->secondaryOwnerNationTag18 != nationTag) {
      continue;
    }
    if (g_abGateFlagQualifies[tile->gateFlag] == 0) {
      continue;
    }
    short maxValue = 0;
    for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
      signed char resourceType = tile->resourceTypeByEdge[edgeIndex];
      if (resourceType == -1) {
        continue;
      }
      if (g_anResourceTypeRequiredOrderType[resourceType] != orderType) {
        continue;
      }
      if (g_abResourceTypeAlwaysQualifies[resourceType] == 0 &&
          tile->ownerNationTag04 != nationTag) {
        continue;
      }
      short value =
          g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationTag][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    signed char lowNibble = tile->developmentClassNibbles0c & 0xf;
    if (lowNibble < maxValue) {
      tile->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005159b0
void TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA(
    TCivUnit* pCivilianOrderEntry) {
  this->field9 = 1;
  for (int i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].recruitSearchVisited0e = 1;
  }

  short nationTag = pCivilianOrderEntry->field_18;
  StrategicTileIndex tileIndex = pCivilianOrderEntry->tileIndex06;

  // Each researched technology enables another terrain in the shared capability profile.
  // The listing writes 0x00696f0c/0a/0b: indices 4/2/3 from the table base 0x00696f08.
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x06] == 2) {
    g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainSwamp] = 1;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x0c] == 2) {
    g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainHills] = 1;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x17] == 2) {
    g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainMountain] = 1;
  }

  if (g_abStrategicTerrainSeedGateProfileA[terrainStateTable[tileIndex].GetTerrainKind()] != 0) {
    StrategicTileIndex* neighbors = BuildHexAreaTileIndexList(tileIndex, 1);
    unsigned char directionBit = 0;
    for (int d = 0; d < 6; ++d) {
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (g_abStrategicTerrainSeedGateProfileA[neighbor->GetTerrainKind()] != 0 &&
          neighbor->ownerNationTag04 == nationTag &&
          ((1 << directionBit) & terrainStateTable[tileIndex].adjacencyBits06) == 0) {
        neighbor->recruitSearchVisited0e = 0;
      }
      ++directionBit;
    }
    delete[] neighbors;
  }
}

// FUNCTION: IMPERIALISM 0x00515b10
void TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB(
    TCivUnit* pCivilianOrderEntry) {
  StrategicTileIndex tileIndex = pCivilianOrderEntry->tileIndex06;
  short nationTag = pCivilianOrderEntry->field_18;

  unsigned char terrainKindGate[kStrategicTerrainCount] = {1, 1, 0, 0, 0, 0, 1, 1};
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x06] == 2) {
    terrainKindGate[kStrategicTerrainSwamp] = 1;
    terrainKindGate[kStrategicTerrainWater] = 0;
    terrainKindGate[kStrategicTerrainDesert] = 1;
    terrainKindGate[kStrategicTerrainFarmland] = 1;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x0c] == 2) {
    terrainKindGate[kStrategicTerrainPlains] = 1;
    terrainKindGate[kStrategicTerrainForest] = 1;
    terrainKindGate[kStrategicTerrainHills] = 1;
    terrainKindGate[kStrategicTerrainMountain] = 0;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x17] == 2) {
    terrainKindGate[kStrategicTerrainMountain] = 1;
  }

  this->field9 = 1;
  for (int i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].recruitSearchVisited0e = 1;
  }

  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  if (terrainKindGate[tile->GetTerrainKind()] != 0) {
    if (tile->regionSubtypeTag05 == -1 || cityScoreTable[tile->cityRecordIndex].fortLevel03 < 3) {
      tile->recruitSearchVisited0e = 0;
    }

    StrategicTileIndex* neighbors = BuildHexAreaTileIndexList(tileIndex, 1);
    unsigned char directionBit = 0;
    for (int d = 0; d < 6; ++d) {
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (terrainKindGate[neighbor->GetTerrainKind()] != 0 &&
          neighbor->ownerNationTag04 == nationTag &&
          ((1 << directionBit) & tile->adjacencyBits06) == 0) {
        neighbor->recruitSearchVisited0e = 0;
      }
      ++directionBit;
    }
    delete[] neighbors;
  }
}

// FUNCTION: IMPERIALISM 0x00515d60
void TMapMgr::ApplyUnitMovementClassForTileIfValid(int tileIndex) {
  if (tileIndex != -1) {
    g_pMapContextActionManager->HasEligibleStationedUnitInRegion(static_cast<short>(tileIndex));
  }
}

// FUNCTION: IMPERIALISM 0x00515db0
void TMapMgr::ClearPerTileByte0FForAllMapTiles() {
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].perTileVisitedFlag0f = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515de0
void TMapMgr::NoOpVirtualSlot2D(int param_1, int param_2, int param_3) {
  (void)param_1;
  (void)param_2;
  (void)param_3;
}

// FUNCTION: IMPERIALISM 0x00515e00
void TMapMgr::SetMapTileStateByteAndNotifyObserver(StrategicTileIndex tileIndex, int stateByte) {
  terrainStateTable[tileIndex].tileActionState16 =
      static_cast<MapTileActionStateStorage>(stateByte);
  if (g_pUiRuntimeContext->mapUberPictureF0 != 0) {
    g_pUiRuntimeContext->mapUberPictureF0->InvalidateTile(tileIndex);
  }
}

// Verified against 0x0053e7bf's callsite (TDefendProvinceMission::
// ComputeCrossNationSupportVectorScore): despite the Ghidra-provisional name, this
// checks whether regionIndex appears in nodeContext's adjacent-region list, not
// anything about movement classes -- kept the name per Hard Rule 6 (no clean
// replacement name yet), documented here instead.
// FUNCTION: IMPERIALISM 0x00515e50
char TMapMgr::TileHasMovementClassId(int nodeContext, int regionIndex) {
  const Province& record = cityScoreTable[nodeContext];
  for (int i = 0; i < record.adjacentRegionCount08; ++i) {
    if (record.adjacentRegionIds0A[i] == regionIndex) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00515ec0
void TMapMgr::AssignCityRecordDisplayName(ProvinceIndex cityRecordIndex, CString* dest) {
  *dest = cityScoreTable[cityRecordIndex].cityNameA4;
}

// FUNCTION: IMPERIALISM 0x00515f40
void TMapMgr::SetGlobalMapCellSharedLabel(ProvinceIndex cityRecordIndex, CString* name) {
  CString* dest = reinterpret_cast<CString*>(reinterpret_cast<char*>(cityScoreTable) +
                                             cityRecordIndex * 0xa8 + 0xa4);
  *dest = *name;
}

// FUNCTION: IMPERIALISM 0x00515f80
void TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags(ProvinceIndex cityRecordIndex,
                                                          int newTileIndex) {
  Province* city = &cityScoreTable[cityRecordIndex];

  short oldTileIndex = city->cityTileIndex04;
  if (oldTileIndex != -1) {
    TTerrainStateRecordView* oldTile = &terrainStateTable[oldTileIndex];
    oldTile->activeFlags1c = 0;
    oldTile->gateFlag =
        static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(oldTileIndex));
    oldTile->resourceTypeByEdge[0] = 0x11;
  }

  TTerrainStateRecordView* newTile = &terrainStateTable[newTileIndex];
  newTile->activeFlags1c = 2;
  city->cityTileIndex04 = newTileIndex;
  newTile->activeFlags1c |= 0x20;
  newTile->gateFlag =
      static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(newTileIndex));

  for (int i = 0; i < city->linkedRegionCount; ++i) {
    TTerrainStateRecordView* linkedTile = &terrainStateTable[city->linkedTileIndices42[i]];
    if (linkedTile->activeFlags1c & 0x20) {
      linkedTile->activeFlags1c &= ~0x20;
    }
  }

  UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(cityRecordIndex);
}

// FUNCTION: IMPERIALISM 0x00516090
StrategicTileIndex TMapMgr::FindLinkedTileForAdjacentProvince(ProvinceIndex cityRecordIndex,
                                                              ProvinceIndex regionId) {
  Province* city = &cityScoreTable[cityRecordIndex];
  for (int i = 0; i < 12; ++i) {
    if (city->adjacentRegionIds0A[i] == regionId) {
      return city->adjacentRegionAnchorTiles22[i];
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00516100
void TMapMgr::SetCapitalCityDevelopmentStageIfValidNationSlot(int nationSlotParam, int param_2) {
  (void)param_2;
  short capitalTileIndex =
      static_cast<short>(g_apTerrainTypeDescriptorTable[nationSlotParam]->homeTileIndex);
  short cityRecordIndex = terrainStateTable[capitalTileIndex].cityRecordIndex;
  if (nationSlotParam < 7) {
    cityScoreTable[cityRecordIndex].developmentStage = 2;
  }
}

// Mountain selects a per-spriteVariantIndex01 column; every other strategic terrain kind
// always reads column 0 of the same gateFlag row.
// FUNCTION: IMPERIALISM 0x00516150
short TMapMgr::LookupTileSpriteVariantOffsetByTerrainAndGate(StrategicTileIndex nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  if (tile->GetTerrainKind() == kStrategicTerrainMountain) {
    return g_awTileSpriteVariantOffsetTable38[tile->gateFlag][tile->spriteVariantIndex01];
  }
  return g_awTileSpriteVariantOffsetTable38[tile->gateFlag][0];
}

// adjacencyMaskB0b != 0 forces column 0 (no per-tile variant); otherwise the table is
// indexed directly by spriteVariantIndex01 (single row, no gateFlag dimension).
// FUNCTION: IMPERIALISM 0x005161a0
short TMapMgr::LookupTileSpriteVariantOffsetByAdjacencyMaskB(StrategicTileIndex nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  if (tile->adjacencyMaskB0b != 0) {
    return g_awTileSpriteVariantOffsetTable39[0];
  }
  return g_awTileSpriteVariantOffsetTable39[tile->spriteVariantIndex01];
}

// FUNCTION: IMPERIALISM 0x005161e0
short TMapMgr::LookupTileSpriteVariantOffsetByGateAndVariant(StrategicTileIndex nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  return g_awTileSpriteVariantOffsetTable3a[tile->gateFlag][tile->spriteVariantIndex01];
}

// FUNCTION: IMPERIALISM 0x00516220
short TMapMgr::LookupTileSpriteVariantOffsetByGateAndVariantAlt(StrategicTileIndex nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  return g_awTileSpriteVariantOffsetTable3b[tile->gateFlag][tile->spriteVariantIndex01];
}

// FUNCTION: IMPERIALISM 0x00516260
short TMapMgr::LookupAdjacencyBitmaskVariantByDirection(char bitmaskIndex, char direction) {
  short table[64][7] = {
      {0, 0, 0, 0, 0, 0, 0},  {1, 2, 2, 0, 0, 0, 0},  {2, 0, 3, 3, 0, 0, 0},
      {3, 2, 1, 3, 0, 0, 0},  {4, 0, 0, 2, 2, 0, 0},  {5, 2, 0, 2, 2, 0, 0},
      {6, 0, 3, 1, 2, 0, 0},  {7, 2, 1, 1, 2, 0, 0},  {8, 0, 0, 0, 3, 3, 0},
      {9, 2, 2, 0, 3, 3, 0},  {10, 0, 3, 3, 3, 3, 0}, {11, 2, 1, 3, 3, 3, 0},
      {12, 0, 0, 2, 1, 3, 0}, {13, 2, 2, 2, 1, 3, 0}, {14, 0, 3, 1, 1, 3, 0},
      {15, 2, 1, 1, 1, 3, 0}, {16, 0, 0, 0, 0, 2, 2}, {17, 2, 2, 0, 0, 2, 2},
      {18, 0, 3, 3, 0, 2, 2}, {19, 2, 1, 3, 0, 2, 2}, {20, 0, 0, 2, 2, 2, 2},
      {21, 2, 2, 2, 2, 2, 2}, {22, 0, 3, 1, 2, 2, 2}, {23, 2, 1, 1, 2, 2, 2},
      {24, 0, 0, 0, 3, 1, 2}, {25, 2, 2, 0, 3, 1, 2}, {26, 0, 3, 3, 3, 1, 2},
      {27, 2, 1, 3, 3, 1, 2}, {28, 0, 0, 2, 1, 1, 2}, {29, 2, 2, 2, 1, 1, 2},
      {30, 0, 3, 1, 1, 1, 2}, {31, 2, 1, 1, 1, 1, 2}, {32, 3, 0, 0, 0, 0, 3},
      {33, 1, 2, 0, 0, 0, 3}, {34, 3, 3, 3, 0, 0, 3}, {35, 1, 1, 3, 0, 0, 3},
      {36, 3, 0, 2, 2, 0, 3}, {37, 1, 2, 2, 2, 0, 3}, {38, 3, 3, 1, 2, 0, 3},
      {39, 1, 1, 1, 2, 0, 3}, {40, 3, 0, 0, 3, 3, 3}, {41, 1, 2, 0, 3, 3, 3},
      {42, 3, 3, 3, 3, 3, 3}, {43, 1, 1, 3, 3, 3, 3}, {44, 3, 0, 2, 1, 3, 3},
      {45, 1, 2, 2, 1, 3, 3}, {46, 3, 3, 1, 1, 3, 3}, {47, 1, 1, 1, 1, 3, 3},
      {48, 3, 0, 0, 0, 2, 1}, {49, 1, 2, 0, 0, 2, 1}, {50, 3, 3, 3, 0, 2, 1},
      {51, 1, 1, 3, 0, 2, 1}, {52, 3, 0, 2, 2, 2, 1}, {53, 1, 2, 2, 2, 2, 1},
      {54, 3, 3, 1, 2, 2, 1}, {55, 1, 1, 1, 2, 2, 1}, {56, 3, 0, 0, 3, 1, 1},
      {57, 1, 2, 0, 3, 1, 1}, {58, 3, 3, 3, 3, 1, 1}, {59, 1, 1, 3, 3, 1, 1},
      {60, 3, 0, 2, 1, 1, 1}, {61, 1, 2, 2, 1, 1, 1}, {62, 3, 3, 1, 1, 1, 1},
      {63, 1, 1, 1, 1, 1, 1},
  };
  return table[static_cast<int>(bitmaskIndex)][static_cast<int>(direction)];
}

// FUNCTION: IMPERIALISM 0x00517410
int TMapMgr::MapImprovementOffsetFromAdjacencyVariant(char bitmaskIndex, char direction,
                                                      char useAltOffset) {
  if (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) == 0) {
    return 0;
  }
  if (useAltOffset == 0) {
    return (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) + 0x15) << 6;
  }
  return (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) + 0x20) << 6;
}

// FUNCTION: IMPERIALISM 0x00517480
short TMapMgr::MapImprovementOffsetFromAdjacencyVariantTriple(char bitmaskIndex, char direction,
                                                              short param3) {
  if (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) == 0) {
    return 0;
  }
  short offset = LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction);
  offset = (offset + 0x29) << 6;
  if (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) == 1) {
    if (param3 == 0x33 || param3 == 0x36 || param3 == 0x3a || param3 == 0x39) {
      offset += 0xc0;
    }
  }
  return offset;
}

// FUNCTION: IMPERIALISM 0x00517520
short TMapMgr::GetFixedConstant0xc80() {
  return 0xc80;
}

// FUNCTION: IMPERIALISM 0x00517540
int TMapMgr::GetMapImprovementOffsetByActiveFlagsAndCityStage(StrategicTileIndex tileIndex,
                                                              short categoryCode) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  unsigned char flags = tile->activeFlags1c;
  if (categoryCode < 7) {
    if (flags & 1) {
      return 0x6c0;
    }
    if (flags & 2) {
      short cityRecordIndex = tile->cityRecordIndex;
      switch (cityScoreTable[cityRecordIndex].developmentStage) {
      case 0:
        return 0x700;
      case 1:
        return 0x740;
      case 2:
        return 0x780;
      }
    }
    return 0;
  }
  if (flags & 1) {
    return 0x9c0;
  }
  if (flags & 2) {
    return 0x980;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00517600
short TMapMgr::GetMapImprovementOffsetByTownTransportLink(StrategicTileIndex tileIndex,
                                                          int unusedParam2) {
  (void)unusedParam2;
  unsigned char flags = terrainStateTable[tileIndex].activeFlags1c;
  TTown* town = FindTownMarkerForTileByOwnerNation(tileIndex);
  unsigned char linked = (town != nullptr) ? town->transportLinkedFlag4c : 1;
  if (flags & 4) {
    if (flags & 0x10) {
      return linked ? 0x840 : 0xa40;
    }
    return linked ? 0x880 : 0xa00;
  }
  if (flags & 0x10) {
    return linked ? 0x7c0 : 0x800;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005176a0
int TMapMgr::GetMapImprovementBitmapRowOffsetForIndex(int index) {
  return (index + 0x23) << 6;
}

// FUNCTION: IMPERIALISM 0x005176c0
int TMapMgr::ComputeTerrainRecordByteOffsetForIndex(int index) {
  return (index + index * 8) << 2;
}

// FUNCTION: IMPERIALISM 0x005176e0
short TMapMgr::GetMapImprovementTierBucketOffset(short tier) {
  if (tier < 7) {
    return tier * 9;
  }
  return 0x3f;
}

// FUNCTION: IMPERIALISM 0x00517710
short TMapMgr::ApplyMapImprovementSelectionState(TCivUnit* civUnit) {
  if (civUnit->field_1C != 0) {
    return GetMapImprovementSpriteBaseOffset(civUnit->orderType, 1, 0);
  }
  char idleState = static_cast<char>(civUnit->IsInIdleSelectionState());
  return GetMapImprovementSpriteBaseOffset(civUnit->orderType, 0, idleState);
}

// FUNCTION: IMPERIALISM 0x00517780
short TMapMgr::GetMapImprovementSpriteBaseOffset(short param_1, char param_2, char param_3) {
  if (param_2 != 0) {
    return 0x6c0;
  }
  short offset = g_anMapImprovementSpriteClassByOrderType[param_1] << 6;
  if (param_3 == 0) {
    offset += 0x480;
  }
  return offset;
}

// FUNCTION: IMPERIALISM 0x005177d0
int TMapMgr::GetMapImprovementTileOffsetFromClass(char classCode, int unusedParam2) {
  (void)unusedParam2;
  return classCode * 16;
}

// FUNCTION: IMPERIALISM 0x005177f0
short TMapMgr::GetMapImprovementTileSpriteOffset(StrategicTileIndex tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  unsigned char flags = tile->activeFlags1c;
  if (flags & 1) {
    if (tile->ownerNationTag04 < 7) {
      return (tile->ownerNationTag04 + 0x16) << 4;
    }
    return 0x1d << 4;
  }
  if ((flags >> 5) & 1) {
    if (tile->ownerNationTag04 < 7) {
      return (tile->ownerNationTag04 * 2 + 0x40) << 4;
    }
    return 0x4e << 4;
  }
  if ((flags >> 2) & 1) {
    if (tile->ownerNationTag04 < 7) {
      return (tile->ownerNationTag04 + 0x26) << 4;
    }
    return 0x2d << 4;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005178c0
void TMapMgr::ResetAllTileMarkerSlotIndicesToSentinel() {
  signed char* markerSlot = &terrainStateTable[0].markerSlotIndex10;
  for (int tileCount = 0x1950; tileCount != 0; --tileCount) {
    *markerSlot = -1;
    markerSlot += sizeof(TTerrainStateRecordView);
  }
}

// FUNCTION: IMPERIALISM 0x005178f0
int TMapMgr::ComputeRepresentativeTileIndexForNationWithWrapBias(short nationSlot, char wrapBias) {
  char* tileTable = reinterpret_cast<char*>(terrainStateTable);
  char* cityTable = reinterpret_cast<char*>(cityScoreTable);
  unsigned int colSum = 0;
  int rowSum = 0;
  unsigned int tileCount = 0;
  int westCount = 0;
  unsigned int eastCount = 0;

  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    int tileByteOffset = tileIndex * 0x24;
    char ownerNationTag = tileTable[tileByteOffset + 4];
    if (ownerNationTag != nationSlot) {
      continue;
    }
    char includeTile = 1;
    if (nationSlot < 0x17 && g_apTerrainTypeDescriptorTable[nationSlot] != 0 &&
        g_apTerrainTypeDescriptorTable[nationSlot]->homeTileIndex != -1) {
      short nationHomeTile =
          static_cast<short>(g_apTerrainTypeDescriptorTable[nationSlot]->homeTileIndex);
      short tileCityLink = *reinterpret_cast<short*>(tileTable + tileByteOffset + 0x14);
      char tileCityByte = cityTable[0xa3 + static_cast<int>(tileCityLink) * 0xa8];
      short nationTileCityLink =
          *reinterpret_cast<short*>(tileTable + nationHomeTile * 0x24 + 0x14);
      char nationCityByte = cityTable[0xa3 + static_cast<int>(nationTileCityLink) * 0xa8];
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

  if (westCount >= 1 && static_cast<int>(eastCount) >= 1) {
    if (wrapBias == 0) {
      tileCount = 0;
      rowSum = 0;
      colSum = 0;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (tileTable[tileIndex * 0x24 + 4] != nationSlot) {
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
  if (nationSlot < 0x17 && g_apTerrainTypeDescriptorTable[nationSlot] != 0) {
    TLongintList* ownedRegions = g_apTerrainTypeDescriptorTable[nationSlot]->ownedRegionList;
    if (ownedRegions != 0 && ownedRegions->GetSize() > 0) {
      int lastMatch = -1;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (static_cast<signed char>(tileTable[tileIndex * 0x24 + 4]) == nationSlot) {
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

// FUNCTION: IMPERIALISM 0x00517c30
char TMapMgr::AreNationsBorderLinked(int nationA, int nationB) {
  TLongintList* regionList = g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList;
  if (regionList->GetSize() < 1) {
    return 0;
  }
  int ordinal = 1;
  do {
    int regionId = regionList->At(ordinal);
    Province* record = &cityScoreTable[regionId];
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
  } while (ordinal <= regionList->GetSize());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00517dd0
bool TMapMgr::HasDirectOrFallbackLinkedNodeType(ProvinceIndex cityRecordIndex, int nationCode,
                                                char allowFallback) {
  Province* record = &cityScoreTable[cityRecordIndex];
  int neighborCount = record->adjacentRegionCount08;

  if (allowFallback == 0 || nationCode > 6) {
    for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
      short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
      if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationCode) {
        return true;
      }
    }
    return false;
  }

  for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
    short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
    if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationCode) {
      return true;
    }
  }

  for (int minorSlot = 7; minorSlot < 0x17; ++minorSlot) {
    if (g_apTerrainTypeDescriptorTable[minorSlot] != nullptr &&
        g_apSecondaryNationStateSlots[minorSlot]->IsEncodedNationSlotMinus200Equal(nationCode)) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
        if (cityScoreTable[neighborRegionId].ownerNationCode00 == minorSlot) {
          return true;
        }
      }
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00517f80
int TMapMgr::CollectSecondDegreeLinksMatchingNodeType(ProvinceIndex cityRecordIndex, int nationTag,
                                                      int* nodeBuffer) {
  int resultCount = 0;
  if (cityScoreTable[cityRecordIndex].adjacentRegionCount08 <= 0) {
    return resultCount;
  }
  for (int outer = 0; outer < cityScoreTable[cityRecordIndex].adjacentRegionCount08; ++outer) {
    short adjacentRegion = cityScoreTable[cityRecordIndex].adjacentRegionIds0A[outer];
    bool matched = false;
    if (cityScoreTable[adjacentRegion].adjacentRegionCount08 > 0) {
      for (int inner = 0; inner < cityScoreTable[adjacentRegion].adjacentRegionCount08; ++inner) {
        if (matched) {
          break;
        }
        if (cityScoreTable[cityRecordIndex].ownerNationCode00 == nationTag) {
          nodeBuffer[resultCount] = adjacentRegion;
          ++resultCount;
          matched = true;
        }
      }
    }
  }
  return resultCount;
}

// FUNCTION: IMPERIALISM 0x00518090
int TMapMgr::CollectSecondDegreeLinksWithMinorNationFallback(ProvinceIndex cityRecordIndex,
                                                             int nationTag, int* nodeBuffer,
                                                             char allowFallback) {
  int resultCount =
      CollectSecondDegreeLinksMatchingNodeType(cityRecordIndex, nationTag, nodeBuffer);
  if (resultCount <= 0 && allowFallback != 0 && nationTag >= 7) {
    int minorIndex;
    for (minorIndex = 0; minorIndex < 16; ++minorIndex) {
      if (g_apMinorNationCapabilityObjects[minorIndex] != 0 &&
          g_apSecondaryNationStateSlots[7 + minorIndex]->IsEncodedNationSlotMinus200Equal(
              nationTag) != 0) {
        resultCount =
            CollectSecondDegreeLinksMatchingNodeType(cityRecordIndex, 7 + minorIndex, nodeBuffer);
        if (resultCount > 0) {
          break;
        }
      }
    }
  }
  return resultCount;
}

// FUNCTION: IMPERIALISM 0x00518130
void TMapMgr::RecomputeTileStrategicScoreHeatmap() {
  int r;
  int i;
  int edge;
  // The original reserves a 6-int scratch here (zero-filled via rep stosd, then seeded
  // {[4]=500,[5]=200}) that is never read afterwards; MSVC5 elides this dead local in the
  // recompile, so its frame is 0x14 smaller and the resulting register/stack-offset
  // allocation diverges from the original even though every instruction matches in kind
  // and order (the FPU diffusion + vtable calls are exact). Left documented, not forced.
  // Per-resource-type weight, pulled from the nation-interaction metric buckets.
  int resourceWeights[17];
  for (int resType = 0; resType < 0x11; ++resType) {
    resourceWeights[resType] = g_pNationInteractionStateManager->GetNationMetricBucketValueByIndex(
        static_cast<short>(resType));
  }

  int regionScores[0x180];

  // Pass 1: base each region's score on the resource yields of its linked tiles.
  Province* region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    int score = 200;
    int linkedCount = region->linkedRegionCount;
    if (linkedCount > 0) {
      StrategicTileIndex* linkedTile = region->linkedTileIndices42;
      do {
        TTerrainStateRecordView* tile = &terrainStateTable[*linkedTile];
        for (edge = 0; edge < 2; ++edge) {
          int resType = tile->resourceTypeByEdge[edge];
          if ((resType != 6 ||
               g_pCityOrderCapabilityState
                       ->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] != 0) &&
              resType != -1) {
            score += g_abUniversityRequirementLevelById[resType][tile->developmentClassNibbles0c] *
                     resourceWeights[resType];
          }
        }
        ++linkedTile;
      } while (--linkedCount != 0);
    }
    regionScores[r] = score;
    region = reinterpret_cast<Province*>(reinterpret_cast<char*>(region) + 0xa8);
  }

  // Pass 2: development-stage bonus.
  char* stagePtr = reinterpret_cast<char*>(cityScoreTable) + 2;
  for (r = 0; r < 0x180; ++r) {
    regionScores[r] += (*stagePtr + 3) * 1000;
    stagePtr += 0xa8;
  }

  // Pass 3: terrain-type descriptor bonuses (first 7 weighted higher than the next 16).
  for (i = 0; i < 7; ++i) {
    if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
      short idx =
          static_cast<short>(g_apTerrainTypeDescriptorTable[i]->GetHomeRegionCityRecordIndex());
      regionScores[idx] += 10000;
    }
  }
  for (i = 7; i < 23; ++i) {
    if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
      short idx =
          static_cast<short>(g_apTerrainTypeDescriptorTable[i]->GetHomeRegionCityRecordIndex());
      regionScores[idx] += 8000;
    }
  }

  // Pass 4: store each region's score, then diffuse a weighted share of each adjacent
  // region's score back into it.
  region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    region->cityScoreValue = regionScores[r];
    for (i = region->adjacentRegionCount08 - 1; i >= 0; --i) {
      short adjIdx = region->adjacentRegionIds0A[i];
      region->cityScoreValue = static_cast<int>(
          regionScores[adjIdx] * g_TileHeatmapNeighborDiffusionFactor + region->cityScoreValue);
    }
    region = reinterpret_cast<Province*>(reinterpret_cast<char*>(region) + 0xa8);
  }

  // Pass 5: cityScoreTotal = mean region score.
  cityScoreTotal = 0;
  region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    cityScoreTotal += region->cityScoreValue;
    region = reinterpret_cast<Province*>(reinterpret_cast<char*>(region) + 0xa8);
  }
  cityScoreTotal = cityScoreTotal / 0x180;
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

// FUNCTION: IMPERIALISM 0x005184e0
short TMapMgr::GetProvinceUnitOrderWeight(ProvinceIndexStorage provinceId) {
  // Retail body ignores the province and returns the constant weight 0x21 (33);
  // mission scoring converts it to float for the accumulate dampening factor.
  (void)provinceId;
  return 0x21;
}

// FUNCTION: IMPERIALISM 0x00518540
char TMapMgr::LoadScenarioMapStateFromTableResource(int scenarioIndex) {
  CString scenarioPath;
  g_pUiViewManager->BuildScenarioPathForModeAndIndex(scenarioIndex, 1, &scenarioPath);
  if (TryGetFileMetadataForPath(&scenarioPath) == 0) {
    return 0;
  }

  CFile* stream = g_pUiViewManager->LoadTableResourceStreamByName(scenarioPath);

  // Raw terrain table: 0x1950 records x 0x24 bytes.
  int byteCount = 0x38f40;
  int nameCapacity = 0x20;
  g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, terrainStateTable, &byteCount);

  // City records: the 0xa4-byte POD prefix, then a 2-byte length word and the 0x20-byte
  // name text, assigned into the CString member.
  byteCount = 0xa4;
  int recordCount = 0x180;
  Province* record = cityScoreTable;
  do {
    int nameLengthBytes;
    char nameText[0x20];
    g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, record, &byteCount);
    nameLengthBytes = 2;
    g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, nameText, &nameLengthBytes);
    g_pUiViewManager->ReadResourceStreamIntoBufferAndAdvance(stream, nameText, &nameCapacity);
    CString cityName(nameText);
    record->cityNameA4 = cityName;
    ++record;
    --recordCount;
  } while (recordCount != 0);
  g_pUiViewManager->ReleaseResourceStreamIfNotNull(stream);

  // Endian fixup of the per-tile short fields + clear the transient order chain.
  {
    TTerrainStateRecordView* tile = terrainStateTable;
    int tileCount = 0x1950;
    do {
      SwapShortBytes(&tile->cityRecordIndex);
      SwapShortBytes(&tile->tileActionOrdinal1a);
      SwapShortBytes(&tile->activeFlags1c);
      tile->firstCivilianOrder20 = 0;
      ++tile;
      --tileCount;
    } while (tileCount != 0);
  }

  ByteSwapCityScoreTableShortFields(cityScoreTable);

  // Reset the water-adjacency masks on the first tile of each of the 60 rows (the
  // horizontal wrap column).
  int row;
  for (row = 0; row < 0x3c; ++row) {
    short rowTile = static_cast<short>(row * 0x6c);
    if (terrainStateTable[rowTile].GetTerrainKind() == kStrategicTerrainWater) {
      terrainStateTable[rowTile].waterAdjacencyMask09 = 0;
      terrainStateTable[rowTile].adjacencyMaskB0b = 0;
      terrainStateTable[rowTile].spriteVariantIndex01 = 0;
    }
  }
  return 1;
}

// Byte-swaps the big-endian short fields of every city-score record after the raw table
// load: cityTileIndex04/lastTurnTick, the paired adjacent-record id/anchor-tile arrays,
// the secondary/primary neighbor links, all 0x20 linkedTileIndices, and the ten
// resource-development counters.
// FUNCTION: IMPERIALISM 0x00518840
void ByteSwapCityScoreTableShortFields(Province* table) {
  Province* record = table;
  int recordCount = 0x180;
  do {
    SwapShortBytes(&record->cityTileIndex04);
    SwapShortBytes(&record->lastTurnTick);
    int k = 0xc;
    short* idSlot = record->adjacentRegionIds0A;
    do {
      SwapShortBytes(&idSlot[0]);
      SwapShortBytes(&idSlot[0xc]);
      ++idSlot;
      --k;
    } while (k != 0);
    SwapShortBytes(&record->secondaryNeighborTileIndex3e);
    SwapShortBytes(&record->primaryNeighborTileIndex40);
    k = 0x20;
    StrategicTileIndex* linkedSlot = record->linkedTileIndices42;
    do {
      SwapShortBytes(linkedSlot);
      ++linkedSlot;
      --k;
    } while (k != 0);
    k = 0xa;
    short* devSlot = record->resourceDevelopmentCounts82;
    do {
      SwapShortBytes(devSlot);
      ++devSlot;
      --k;
    } while (k != 0);
    ++record;
    --recordCount;
  } while (recordCount != 0);
}

// FUNCTION: IMPERIALISM 0x00518960
void TMapMgr::SetRegionDevelopmentStageByte(short regionId, unsigned char stage) {
  cityScoreTable[regionId].developmentStage = stage;
}

// FUNCTION: IMPERIALISM 0x00518990
void TMapMgr::ResetTileToBaseTransportFlag(StrategicTileIndex tileIndex) {
  int tile = tileIndex;
  SetRegionTileSubtypeAndRefreshNeighborFlags(terrainStateTable[tile].cityRecordIndex, tile);
  if (terrainStateTable[tile].activeFlags1c & 4) {
    g_pActiveMapOrderContext->RemovePortZoneByTile(tileIndex);
  }
  terrainStateTable[tile].activeFlags1c = 1;
  terrainStateTable[tile].activeFlags1c |= 0x20;
  InitializeTileNeighborConnectionMaskIfNeeded(tile);
}

// Verified against the disassembly: returns TRUE as soon as it finds a linked
// region whose terrainStateTable activeFlags1c bit 2 is SET, and FALSE if
// linkedRegionCount<=0 -- the OPPOSITE of what the Ghidra-provisional name
// implies ("all clear" would return true only when none are set). Kept the name
// per Hard Rule 6 pending a confident replacement; documented the real behavior
// here instead of renaming on a single read.
// FUNCTION: IMPERIALISM 0x00518a20
char TMapMgr::AreAllLinkedEntriesTerrainFlagBit2Clear(int regionIndex) {
  const Province& record = cityScoreTable[regionIndex];
  for (int i = 0; i < record.linkedRegionCount; ++i) {
    unsigned char flags = terrainStateTable[record.linkedTileIndices42[i]].activeFlags1c;
    if ((flags >> 2) & 1) {
      return 1;
    }
  }
  return 0;
}
// FUNCTION: IMPERIALISM 0x00518b40
int TMapMgr::CalculateDeveloperTilePurchaseCost(StrategicTileIndex nTileIndex) {
  int total = 0;
  int edge = 0;
  do {
    short resourceType = terrainStateTable[nTileIndex].resourceTypeByEdge[edge];
    if (resourceType != -1) {
      if (resourceType < 0x11) {
        total = total +
                g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceType) * 0x14;
      } else if (resourceType == 0x15) {
        total = total + 10000;
      } else if (resourceType == 0x16) {
        total = total + 4000;
      }
    }
    edge = edge + 1;
  } while (edge < 2);
  return total;
}

// FUNCTION: IMPERIALISM 0x00518bd0
void TMapMgr::MarkAdjacentHexOrderDirectionAndSelectTile(int tileIndex, int contextArg, char flag) {
  short anchorTile = cityScoreTable[contextArg].cityTileIndex04;
  short direction =
      GetDirectionFrom(anchorTile, g_pGlobalMapState->cityScoreTable[tileIndex].cityTileIndex04);

  int row = anchorTile / 0x6c;
  int col = anchorTile % 0x6c;

  short hexAreaX =
      static_cast<short>(row % 2 + col * 2 +
                         g_Build_Hex_Area_LookupTable_00696E70[direction < 0    ? direction + 6
                                                               : direction <= 5 ? direction
                                                                                : direction - 6]);

  short hexAreaY =
      static_cast<short>(g_Build_Hex_Area_LookupTable_00696E80[direction < 0    ? direction + 6
                                                               : direction <= 5 ? direction
                                                                                : direction - 6] +
                         row);

  if (hexAreaX > 0xd7) {
    hexAreaX -= 0xd9;
  } else if (hexAreaX < 0) {
    hexAreaX += 0xd8;
  }

  if (hexAreaY < 0) {
    hexAreaY = 0;
  } else if (hexAreaY > 0x3b) {
    hexAreaY = 0x3b;
  }

  short finalTileIndex = static_cast<short>(hexAreaX / 2 + hexAreaY * 0x6c);
  if (finalTileIndex < 0 || finalTileIndex >= 0x1950) {
    finalTileIndex = -1;
  }

  if (finalTileIndex != -1) {
    signed char directionCode = static_cast<signed char>((direction + 3) % 6 + 1);
    if (flag != 0) {
      directionCode += 6;
    }
    g_pGlobalMapState->terrainStateTable[finalTileIndex].perTileVisitedFlag0f = directionCode;
    if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
      g_pUiRuntimeContext->mapUberPictureF0->InvalidateTile(finalTileIndex);
    }
  }
}

namespace {
// Indexed by (gateFlag - 1) for terrainStateTable gateFlag values in [1,15]; groups a
// linked region's gate type into one of the buckets tallied by
// ClassifyCityGateTerrainComposition below (bucket 7, gateFlag 14, scores nothing).
const unsigned char kGateFlagScoreBucket[15] = {0, 0, 0, 0, 1, 1, 2, 2, 2, 3, 4, 2, 2, 7, 2};
} // namespace

// FUNCTION: IMPERIALISM 0x00518d90
void TMapMgr::MarkDirectionalMapOverlayFlagsForNationOrders() {
  // Real prefix: clears perTileVisitedFlag0f across all 0x1950 tiles. Same body as the
  // standalone ClearPerTileByte0FForAllMapTiles (0x515db0), duplicated inline here to
  // match the original, which inlines it rather than sharing one out-of-line call.
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].perTileVisitedFlag0f = 0;
  }

  // Per active-nation order (TUnit::field_C is the order's own city-record index;
  // tileIndex06 is read as the "stationed province id" for this unit type, per
  // TMilitaryUnit.h -- both are city-record indices, not raw map tiles, resolving the
  // earlier "unrecovered geometry helper" TODO): mark the hex-adjacent tile in the
  // direction from the order's city toward the stationed province with a
  // war/peace-coded direction overlay. Same computation as the real, separately-
  // addressed sibling MarkAdjacentHexOrderDirectionAndSelectTile (0x518bd0) -- the
  // original inlines it at both call sites rather than sharing one out-of-line body,
  // so it is duplicated here rather than called, to match that shape.
  short activeNationId = g_pSimMgr->GetActiveNationId();
  CIterator cursor(g_apNationStates[activeNationId]->militaryUnitList44);
  TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
  while (cursor.More()) {
    if (unit->field_C != -1) {
      bool atWar = g_pDiplomacyTurnStateManager->IsNationPairAtWar(
          activeNationId, cityScoreTable[unit->field_C].ownerNationCode00);

      short anchorTile = cityScoreTable[unit->field_C].cityTileIndex04;
      short direction =
          GetDirectionFrom(anchorTile, cityScoreTable[unit->tileIndex06].cityTileIndex04);

      int row = anchorTile / 0x6c;
      int col = anchorTile % 0x6c;

      short hexAreaX = static_cast<short>(
          row % 2 + col * 2 +
          g_Build_Hex_Area_LookupTable_00696E70[direction < 0    ? direction + 6
                                                : direction <= 5 ? direction
                                                                 : direction - 6]);
      short hexAreaY = static_cast<short>(
          g_Build_Hex_Area_LookupTable_00696E80[direction < 0    ? direction + 6
                                                : direction <= 5 ? direction
                                                                 : direction - 6] +
          row);

      if (hexAreaX > 0xd7) {
        hexAreaX -= 0xd9;
      } else if (hexAreaX < 0) {
        hexAreaX += 0xd8;
      }

      if (hexAreaY < 0) {
        hexAreaY = 0;
      } else if (hexAreaY > 0x3b) {
        hexAreaY = 0x3b;
      }

      short finalTileIndex = static_cast<short>(hexAreaX / 2 + hexAreaY * 0x6c);
      if (finalTileIndex < 0 || finalTileIndex >= 0x1950) {
        finalTileIndex = -1;
      }

      if (finalTileIndex != -1) {
        signed char directionCode = static_cast<signed char>((direction + 3) % 6 + 1);
        if (atWar != 0) {
          directionCode += 6;
        }
        terrainStateTable[finalTileIndex].perTileVisitedFlag0f = directionCode;
        if (g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
          g_pUiRuntimeContext->mapUberPictureF0->InvalidateTile(finalTileIndex);
        }
      }
    }
    unit = static_cast<TMilitaryUnit*>(cursor.Advance());
  }
}

// Sum the developer purchase cost of the two edge resources on a tile: for each real
// resource type (< 0x11) weight it via the trade manager's proposal-weight metric (slot
// 0x13) scaled x20; fixed surcharges for the special types 0x15 (10000) and 0x16 (4000).
// (Ghidra mis-attributed this to TCivToolbar; `this->field0c` is TMapMgr::terrainStateTable.)

// FUNCTION: IMPERIALISM 0x00519010
int TMapMgr::ClassifyCityGateTerrainComposition(int cityIndex) {
  const Province& city = cityScoreTable[cityIndex];
  if ((terrainStateTable[city.cityTileIndex04].activeFlags1c & 1) != 0) {
    return 3;
  }

  int tallyA = 0;
  int tallyB = 0;
  int tallyC = 0;
  for (int i = 0; i < city.linkedRegionCount; ++i) {
    short gateFlag = terrainStateTable[city.linkedTileIndices42[i]].gateFlag;
    if (gateFlag < 1 || gateFlag > 15) {
      continue;
    }
    switch (kGateFlagScoreBucket[gateFlag - 1]) {
    case 0:
      ++tallyB;
      break;
    case 1:
      tallyB += 2;
      break;
    case 2:
      tallyA += 2;
      break;
    case 3:
      tallyA += 4;
      break;
    case 4:
      tallyC += 6;
      break;
    default:
      break;
    }
  }

  if (tallyC > tallyA && tallyC > tallyB) {
    return 2;
  }
  return tallyA > tallyB ? 1 : 0;
}

// Debug/script-state dump-and-reset. No xrefs in the retail binary (reached via an
// unrecovered debug hook). Writes a "script" text log of the current map state -- zones,
// ships, per-owner army counts, civilians, port/rail markers, capabilities, labor,
// embargoes, and the year -- then clears the per-tile/per-city runtime state. Confirmed
// flag bits on terrainStateTable[tile].activeFlags1c: 0x04 => "port", 0x10 => "rail",
// each logged (unless bit 0x01 is set) and then cleared.
// FUNCTION: IMPERIALISM 0x00519140
void TMapMgr::DumpAndResetMapScriptState() {
  FILE* logFile = fopen(g_szScriptFileName_006972f8, s_mcflavor_00697238);

  for (TZone* zone = g_pMapActionContextListHead; zone != nullptr; zone = zone->prev18) {
    CString name;
    zone->AssignZoneDisplayNameToOutputRef(&name);
    fprintf(logFile, g_szFmtZone_006972e8, zone->GetContextOrdinalOrInvalid(),
            static_cast<const char*>(name));
  }

  for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
    short shipResource = node->type;
    short shipNation = node->nation;
    short shipOrdinal = node->location->GetContextOrdinalOrInvalid();
    fprintf(logFile, g_szFmtShip_006972d0, shipNation, shipResource, shipOrdinal, 1);
  }

  int recordIndex = 0;
  int byteOffset = 0;
  int i;
  do {
    unsigned char* rec = reinterpret_cast<unsigned char*>(cityScoreTable) + byteOffset;
    rec[8] = 0;
    rec[0x3b] = 0;
    rec[0x3c] = 0;
    *reinterpret_cast<unsigned short*>(rec + 0x3e) = 0xffff;
    *reinterpret_cast<unsigned short*>(rec + 0x40) = 0xffff;
    for (i = 0; i < 12; ++i) {
      *reinterpret_cast<unsigned short*>(rec + 0x0a + i * 2) = 0xffff;
      *reinterpret_cast<unsigned short*>(rec + 0x22 + i * 2) = 0xffff;
    }
    rec[0x3a] = 0;
    for (i = 0; i < 32; ++i) {
      *reinterpret_cast<unsigned short*>(rec + 0x42 + i * 2) = 0xffff;
    }
    int unitNode = *reinterpret_cast<int*>(rec + 0x98);
    if (unitNode != 0) {
      short armyCountByOwner[30];
      for (i = 0; i < 30; ++i) {
        armyCountByOwner[i] = 0;
      }
      do {
        armyCountByOwner[*reinterpret_cast<short*>(unitNode + 4)]++;
        unitNode = *reinterpret_cast<int*>(unitNode + 0x14);
      } while (unitNode != 0);
      for (i = 0; i < 30; ++i) {
        if (armyCountByOwner[i] > 0) {
          fprintf(logFile, g_szFmtArmy_006972bc, recordIndex, i, armyCountByOwner[i]);
        }
      }
    }
    *reinterpret_cast<int*>(rec + 0x98) = 0;
    rec[0xa3] = 0xff;
    byteOffset += 0xa8;
    recordIndex++;
  } while (byteOffset < 0xfc00);

  int tileIndex = 0;
  int tileOffset = 0;
  do {
    unsigned char* tile = reinterpret_cast<unsigned char*>(terrainStateTable) + tileOffset;
    int civilianOrder = *reinterpret_cast<int*>(tile + 0x20);
    if (civilianOrder != 0) {
      fprintf(logFile, g_szFmtCivi_006972ac, *reinterpret_cast<short*>(civilianOrder + 4),
              tileIndex);
      *reinterpret_cast<int*>(tile + 0x20) = 0;
    }
    unsigned short flags = *reinterpret_cast<unsigned short*>(tile + 0x1c);
    if ((flags & 4) != 0) {
      if ((flags & 1) == 0) {
        fprintf(logFile, g_szFmtPort_006972a0, tileIndex);
      }
      tile[0x1c] &= 0xfb;
    }
    flags = *reinterpret_cast<unsigned short*>(tile + 0x1c);
    if ((flags & 0x10) != 0) {
      if ((flags & 1) == 0) {
        fprintf(logFile, g_szFmtRail_00697294, tileIndex);
      }
      tile[0x1c] &= 0xef;
    }
    tile[5] = 0xff;
    tile[0x16] = 0xff;
    tileOffset += 0x24;
    tileIndex++;
  } while (tileOffset < 0x38f40);

  TGreatPower** nationSlot = g_apNationStates;
  int nationIndex = 0;
  int slot;
  do {
    for (slot = 0; slot < 6; ++slot) {
      TCity* city = (*nationSlot != nullptr) ? (*nationSlot)->city : nullptr;
      int value = city->GetBuildingType(static_cast<short>(slot));
      if (static_cast<short>(value) > 0) {
        fprintf(logFile, g_szFmtCapa_00697280, nationIndex, slot, static_cast<short>(value));
      }
    }
    TGreatPower* nation = *nationSlot;
    TCity* laborCity1 = (nation != nullptr) ? nation->city : nullptr;
    TCity* laborCity2 = (nation != nullptr) ? nation->city : nullptr;
    TCity* laborCity3 = (nation != nullptr) ? nation->city : nullptr;
    fprintf(logFile, g_szFmtLabo_00697268, nationIndex,
            *reinterpret_cast<short*>(
                *reinterpret_cast<int*>(reinterpret_cast<char*>(laborCity1->productionSummary1d8) +
                                        0x10) +
                4),
            *reinterpret_cast<short*>(
                *reinterpret_cast<int*>(reinterpret_cast<char*>(laborCity2->productionSummary1d8) +
                                        0x10) +
                6),
            *reinterpret_cast<short*>(
                *reinterpret_cast<int*>(reinterpret_cast<char*>(laborCity3->productionSummary1d8) +
                                        0x10) +
                8));
    for (slot = 0; slot < 0x17; ++slot) {
      short embargo =
          g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(nationIndex, slot);
      if (embargo > 0) {
        embargo =
            g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(nationIndex, slot);
        fprintf(logFile, g_szFmtEmba_00697254, nationIndex, slot, embargo);
      }
    }
    nationSlot++;
    nationIndex++;
  } while (nationSlot < g_apNationStates + 7);

  fprintf(logFile, g_szFmtYear_00697248,
          *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pSimMgr) + 0x2c) / 4);
  fclose(logFile);
  PostWmCloseToMainThreadWindow();
}

// FUNCTION: IMPERIALISM 0x00519610
void TMapMgr::ChooseNationSetupProfilesForOpenSlots(short* outProfileBySlot) {
  // The AI profile ids are handed out in this fixed priority order, and each profile
  // prefers a particular slot-isolation class; the three passes below relax that
  // preference in the profile's own order.
  short profileOrder[7] = {1, 5, 4, 6, 2, 3, 3};
  short preferredIsolationByProfile[7][3] = {{0, 1, 2}, {2, 1, 0}, {0, 1, 2}, {0, 1, 2},
                                             {1, 2, 0}, {1, 2, 0}, {0, 1, 2}};
  short slotIsolation[7];
  short nationRegionClass[0x17];
  int slot;
  int openSlot;
  int recordsLeft;
  int remaining;
  int pass;
  bool assigned;

  // Region class of each nation's territory. Every region a nation owns carries the same
  // class, so the last one seen wins.
  Province* record = cityScoreTable;
  for (recordsLeft = 0x180; recordsLeft != 0; --recordsLeft) {
    if (record->ownerNationCode00 != -1) {
      nationRegionClass[record->ownerNationCode00] = record->regionClassA3;
    }
    ++record;
  }

  // Isolation class of each great-power slot: 2 when its region class is unique, 1 when it
  // is shared only with a minor, 0 when another great power sits on the same class.
  short openSlotCount = 0;
  for (slot = 0; slot < 7; ++slot) {
    slotIsolation[slot] = 2;
    for (int power = 0; power < 7; ++power) {
      if (power != slot && nationRegionClass[power] == nationRegionClass[slot]) {
        slotIsolation[slot] = 0;
      }
    }
    if (slotIsolation[slot] == 2) {
      for (int minor = 7; minor < 0x17; ++minor) {
        if (minor != slot && nationRegionClass[minor] == nationRegionClass[slot]) {
          slotIsolation[slot] = 1;
        }
      }
    }
    if (g_pSimMgr->nationControlModes[slot] == 2) {
      ++openSlotCount;
    }
    outProfileBySlot[slot] = -1;
  }

  // Give each open slot a profile, walking the priority order and taking the first
  // still-unassigned open slot whose isolation class the profile is currently asking for.
  short* profile = profileOrder;
  for (remaining = openSlotCount; remaining > 0; --remaining) {
    assigned = false;
    for (pass = 0; pass < 3 && !assigned; ++pass) {
      for (openSlot = 0; openSlot < 7 && !assigned; ++openSlot) {
        if (g_pSimMgr->nationControlModes[openSlot] == 2 &&
            slotIsolation[openSlot] == preferredIsolationByProfile[*profile][pass] &&
            outProfileBySlot[openSlot] == -1) {
          assigned = true;
          outProfileBySlot[openSlot] = *profile;
        }
      }
    }
    ++profile;
  }

  for (slot = 0; slot < 7; ++slot) {
    if (g_pSimMgr->nationControlModes[slot] != 2) {
      outProfileBySlot[slot] = 3;
    }
  }
}

// Reset a tile's resource-icon edge cache: resolve resourceTypeByEdge[0] from a fixed 16-entry
// lookup indexed by the tile's gateFlag, and force resourceTypeByEdge[1] to 0xff.
// FUNCTION: IMPERIALISM 0x0051da60
void OrphanDeadLeaf_NoRefs_0051da60(StrategicTileIndex nTileIndex) {
  unsigned short lookup[16];
  lookup[0] = 0xffff;
  lookup[1] = 0xffff;
  lookup[2] = 0;
  lookup[3] = 0x14;
  lookup[4] = 5;
  lookup[5] = 0x11;
  lookup[6] = 0x12;
  lookup[7] = 1;
  lookup[8] = 0xffff;
  lookup[9] = 0xffff;
  lookup[10] = 0xffff;
  lookup[11] = 0xffff;
  lookup[12] = 0xffff;
  lookup[13] = 2;
  lookup[14] = 0xffff;
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[nTileIndex];
  tile.resourceTypeByEdge[0] = static_cast<signed char>(lookup[tile.gateFlag]);
  tile.resourceTypeByEdge[1] = static_cast<signed char>(0xff);
}

// FUNCTION: IMPERIALISM 0x0055e360
StrategicTileIndex
TMapMgr::StepHexTileIndexByDirectionWithWrapRules(StrategicTileIndex tileIndex,
                                                  StrategicHexDirectionStorage direction) {
  int col = tileIndex % 0x6c;
  unsigned int row = static_cast<unsigned int>(tileIndex / 0x6c);
  if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionWest) ||
      (direction > EncodeStrategicHexDirection(kStrategicHexDirectionSouthEast) &&
       (row & 1U) == 0U)) {
    col = col - 1;
    if (static_cast<short>(col) < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return -1;
      }
      col = 0x6b;
    }
  } else if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionEast) ||
             (direction < EncodeStrategicHexDirection(kStrategicHexDirectionSouthWest) &&
              (row & 1U) != 0U)) {
    col = col + 1;
    if (col > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return -1;
      }
      col = 0;
    }
  }
  if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionNorthWest) ||
      direction == EncodeStrategicHexDirection(kStrategicHexDirectionNorthEast)) {
    if (static_cast<short>(row) - 1 < 0) {
      return -1;
    }
    row = row - 1U;
  } else if ((direction == EncodeStrategicHexDirection(kStrategicHexDirectionSouthWest) ||
              direction == EncodeStrategicHexDirection(kStrategicHexDirectionSouthEast)) &&
             (row = row + 1U, static_cast<short>(row) > 0x3b)) {
    return -1;
  }
  return static_cast<short>(col + static_cast<int>(row) * 0x6c);
}

// FUNCTION: IMPERIALISM 0x0055e550
bool TMapMgr::StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction) {
  if (direction == kStrategicHexDirectionWest ||
      (direction > kStrategicHexDirectionSouthEast && ((*row) & 1) == 0)) {
    int nextCol = *col - 1;
    *col = nextCol;
    if (nextCol < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return false;
      }
      *col = 0x6b;
    }
  } else if (direction == kStrategicHexDirectionEast ||
             (direction < kStrategicHexDirectionSouthWest && ((*row) & 1) != 0)) {
    int nextCol = *col + 1;
    *col = nextCol;
    if (nextCol > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return false;
      }
      *col = 0;
    }
  }
  if (direction == kStrategicHexDirectionNorthWest ||
      direction == kStrategicHexDirectionNorthEast) {
    int nextRow = *row - 1;
    *row = nextRow;
    if (nextRow < 0) {
      return false;
    }
  } else if (direction == kStrategicHexDirectionSouthWest ||
             direction == kStrategicHexDirectionSouthEast) {
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

StrategicTileIndex TMapMgr::TileIndexFromRowCol(int row, int col) {
  if ((row < 0) || (row > 0x3b) || (col < 0) || (col > 0x6b)) {
    return -1;
  }
  return static_cast<short>(col + row * 0x6c);
}

// Maps a tile index to its owning city/province record (cityScoreTable indexed by the tile's
// cityRecordIndex), or null when the tile belongs to no province.
// FUNCTION: IMPERIALISM 0x00563360
Province* __stdcall GetProvinceByTileIndex(StrategicTileIndex nTileIndex) {
  short recordIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
  if (recordIndex == -1) {
    return nullptr;
  }
  return &g_pGlobalMapState->cityScoreTable[recordIndex];
}

// FUNCTION: IMPERIALISM 0x00563990
StrategicTileIndex TraceTerrainFlowToNearestSeaTile(StrategicTileIndex tileIndex) {
  if (g_pGlobalMapState == 0) {
    return -1;
  }
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  for (int flowVariant = 0; flowVariant < 2; ++flowVariant) {
    short flowType = static_cast<short>(terrainTable[tileIndex].riverSpriteCode);
    if (flowType == 0) {
      return -1;
    }
    if (flowType > 0x1a && flowType < 0x2b) {
      flowType = static_cast<short>(flowType - 0x10);
    }
    if (flowType >= 0xb && flowType <= 0x1a) {
      flowType = *reinterpret_cast<const short*>(kAddrTerrainFlowTypeRemapTable + flowType * 2);
    } else if (flowType >= 0x2b && flowType <= 0x3a) {
      return -1;
    }

    short stepDirection = *reinterpret_cast<const short*>(kAddrTerrainFlowDirectionTable +
                                                          (flowVariant + flowType * 2) * 2);
    short walkTile = tileIndex;
    for (int stepCount = 0; stepCount < 100; ++stepCount) {
      walkTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
      TTerrainStateRecordView& walkRecord = terrainTable[walkTile];
      if (walkRecord.GetTerrainKind() == kStrategicTerrainWater) {
        return walkTile;
      }

      short nextFlowType = static_cast<short>(walkRecord.riverSpriteCode);
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

// Sibling of TraceTerrainFlowToNearestSeaTile: walks the same riverSpriteCode-driven flow chain
// (same type-remap/direction tables, same water-terrain terminal), but from
// `tileIndex`'s own starting owner nation, tracking whether the flow crosses into a
// differently-owned tile before reaching the sea. Tries flow variant 0 first (setting
// crossedBoundary and continuing to walk on a first crossing), then variant 1 (returning 1
// immediately on any crossing); 0xff means no evaluable flow (no road/feature code, or an
// excluded feature range) or 100 steps exhausted on both variants without reaching the sea.
// FUNCTION: IMPERIALISM 0x00563b70
char __stdcall EvaluateTerrainFlowCrossNationBoundaryToSea(StrategicTileIndex tileIndex) {
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  signed char startOwnerNation = terrainTable[tileIndex].ownerNationTag04;

  for (int attempt = 0; attempt < 2; ++attempt) {
    short flowType = static_cast<short>(terrainTable[tileIndex].riverSpriteCode);
    char crossedBoundary = 0;
    if (flowType == 0) {
      return static_cast<char>(0xff);
    }
    if (flowType > 0x1a && flowType < 0x2b) {
      flowType = static_cast<short>(flowType - 0x10);
    }
    if (flowType >= 0xb && flowType <= 0x1a) {
      flowType = *reinterpret_cast<const short*>(kAddrTerrainFlowTypeRemapTable + flowType * 2);
    } else if (flowType >= 0x2b && flowType <= 0x3a) {
      return static_cast<char>(0xff);
    }

    short stepDirection = *reinterpret_cast<const short*>(kAddrTerrainFlowDirectionTable +
                                                          (attempt + flowType * 2) * 2);
    short walkTile = tileIndex;
    for (int stepCount = 0; stepCount < 100; ++stepCount) {
      walkTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
      if (walkTile == -1) {
        return crossedBoundary;
      }
      TTerrainStateRecordView& walkRecord = terrainTable[walkTile];
      if (walkRecord.GetTerrainKind() == kStrategicTerrainWater) {
        return crossedBoundary;
      }

      short nextFlowType = static_cast<short>(walkRecord.riverSpriteCode);
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

      if (startOwnerNation != walkRecord.ownerNationTag04) {
        if (attempt > 0) {
          return 1;
        }
        crossedBoundary = 1;
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
  return static_cast<char>(0xff);
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

void TMapMgr::NotifyCityRecordSlot12C(ProvinceIndex cityRecordIndex) {
  (void)cityRecordIndex;
}
