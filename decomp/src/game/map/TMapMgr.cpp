#include <time.h>
#include "game/resource_domain_types.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"

#include "game/map/TMapMgr.h"
#include "game/core/runtime_prng_seed.h"

#include "game/map_generation/TMapMaker.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/assets/TAssetMgr.h"
#include "game/military/mapped_flavor_text.h"

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
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
#include "game/map/TZone.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/city/TCity.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/globals/global_types.h"
#include "game/globals/map_flow_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/mapped_flavor_literals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"

#include <cstdio>
#include "game/ui_widgets/TTradeMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TTown.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/gfx/ui_invalidation_guard.h"

StrategicTileIndex TraceTerrainFlowToNearestSeaTile(StrategicTileIndex tileIndex);
char __stdcall EvaluateTerrainFlowCrossNationBoundaryToSea(StrategicTileIndex tileIndex);
void NormalizeWrappedMapCoord217x60(short* xCoord, short* yCoord);

// FUNCTION: IMPERIALISM 0x004a4190
TMilitaryUnit* TMapMgr::GetMilitaryMaster(short provinceIndex) {
  if (provinceIndex < 0 || provinceIndex >= 0x180) {
    return nullptr;
  }
  return cityScoreTable[provinceIndex].stationedUnitChain;
}

// Hex direction (0-6) from sourceTile to destTile on the 0x6c(108)-wide map, via each tile's
// doubled-hex-coordinate ("diagonal") position: diag = (row % 2) + col*2. Keep the signed
// remainder: the retail arithmetic preserves a negative parity for negative/sentinel tile values.

IMPLEMENT_DYNCREATE(TMapMgr, TObject)

// FUNCTION: IMPERIALISM 0x0050e3d0
TMapMgr::TMapMgr() : TObject(), cityScoreTable(0), scenarioTagText() {
  field8 = 0;
  strategicMapPalettePreviewReady = false;
  terrainStateTable = 0;
  field9 = 1;
  field24 = false;
  pendingRiverMouthTile = -1;
}

// FUNCTION: IMPERIALISM 0x0050e490
TMapMgr::~TMapMgr() {}

// FUNCTION: IMPERIALISM 0x0050e4e0
void TMapMgr::IMapMgr() {
  field6 = 1;
  if (g_pMacViewMgr->atlas668 == 0) {
    g_pMacViewMgr->BuildStrategicMapRenderAtlasesAndTileMaskCaches();
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
  stream->ReadSharedString(&scenarioTagText, 0x20);
  hexNeighborWrapHorizontally = stream->ReadBoolean();
  stream->ReadBytes(terrainStateTable, 0x38f40);
  int i;
  Province* record = cityScoreTable;
  for (i = 0; i < 0x180; ++i, ++record) {
    stream->ReadBytes(record, 0xa4);
    stream->ReadSharedString(&record->cityNameA4, 0x20);
  }
  for (i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].firstCivilianOrder20 = nullptr;
  }
  for (i = 0; i < 0x180; ++i) {
    cityScoreTable[i].stationedUnitChain = nullptr;
  }
  strategicMapPalettePreviewReady = false;
  if (g_nSaveFormatVersion < 0x32) {
    for (i = 0; i < 0x1950; ++i) {
      terrainStateTable[i].perTileVisitedFlag = 0;
    }
  }
  if (g_nSaveFormatVersion > 0x32) {
    stream->ReadBytes(&pendingRiverMouthTile, 2);
  } else {
    pendingRiverMouthTile = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0050e7a0
void TMapMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&field6, 2);
  stream->WriteBytes(&field8, 1);
  stream->WriteBytes(&field9, 1);
  stream->WriteBytes(&cityScoreTotal, 4);
  stream->WriteSharedString(&scenarioTagText);
  stream->WriteBoolean(hexNeighborWrapHorizontally);
  stream->WriteBytes(terrainStateTable, 0x38f40);
  Province* record = cityScoreTable;
  for (int i = 0; i < 0x180; ++i, ++record) {
    stream->WriteBytes(record, 0xa4);
    stream->WriteSharedString(&record->cityNameA4);
  }
  stream->WriteBytes(&pendingRiverMouthTile, 2);
}

// FUNCTION: IMPERIALISM 0x0050e8b0
void TMapMgr::AllocateAndResetTerrainAndCityScoreTables() {
  if (terrainStateTable == 0) {
    terrainStateTable = new TTerrainStateRecord[0x1950];
    if (terrainStateTable == 0) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0x198);
    }
  }
  int i;
  for (i = 0; i < 0x1950; ++i) {
    TTerrainStateRecord* tile = &terrainStateTable[i];
    tile->SetTerrainKind(kStrategicTerrainUnassigned);
    tile->spriteVariantIndex = 0;
    tile->riverSpriteCode = kRiverSpriteCodeNone;
    tile->formerOwnerNationTag = -1;
    tile->ownerNationTag04 = -1;
    tile->regionSubtypeTag = -1;
    tile->adjacencyBits06 = 0;
    tile->ownerBorderMask = 0;
    tile->cityBorderMask = 0;
    tile->waterAdjacencyMask = 0;
    tile->adjacencyMaskA0a = 0;
    tile->adjacencyMaskB0b = 0;
    tile->developmentClassNibbles = 0;
    tile->pendingDevelopmentFlag = 0;
    tile->perTileVisitedFlag = 0;
    tile->resourceTypeByEdge[0] = -1;
    tile->resourceTypeByEdge[1] = -1;
    tile->gateFlag = -1;
    tile->cityRecordIndex = -1;
    tile->tileActionState16 = kMapTileActionStateNone;
    tile->railFlags = 0;
    tile->secondaryOwnerNationTag = -1;
    tile->tileActionOrdinal = -1;
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
      record->adjacentRegionIds[j] = -1;
    }
    for (j = 0; j < 0xc; ++j) {
      record->adjacentRegionAnchorTiles[j] = -1;
    }
    record->linkedRegionCount = 0;
    record->byte3B = 0;
    record->byte3C = 0;
    record->secondaryNeighborTileIndex = -1;
    record->primaryNeighborTileIndex = -1;
    for (j = 0; j < 0x20; ++j) {
      record->linkedTileIndices42[j] = -1;
    }
    record->resourceDevelopmentCounts[0] = 0;
    record->resourceDevelopmentCounts[1] = 0;
    record->resourceDevelopmentCounts[2] = 0;
    record->resourceDevelopmentCounts[3] = 0;
    record->resourceDevelopmentCounts[4] = 0;
    record->resourceDevelopmentCounts[5] = 0;
    record->resourceDevelopmentCounts[6] = 0;
    record->resourceDevelopmentCounts[7] = 0;
    record->resourceDevelopmentCounts[8] = 0;
    record->resourceDevelopmentCounts[9] = 0;
    record->stationedUnitChain = 0;
    record->resourcePresenceMask = 0;
    record->regionClassA3 = -1;
    record->cityNameA4 = g_szEmptyString;
  }
}

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

  bool sessionActive;
  if (g_pSimMgr->reloadPoliticalMapState || g_pSimMgr->scenarioMapIndexPlusOne != 0) {
    sessionActive = true;
  } else {
    sessionActive = false;
  }
  mapMaker->modeByte2a1 = hexNeighborWrapHorizontally;

  if (sessionActive) {
    if (g_pSimMgr->reloadPoliticalMapState) {
      // Replay path: reload the political tables and refresh every tile in place.
      LoadPoliticalMapRegionSubtypeTableFromResourceStream();
      short tile;
      for (tile = 0; tile < 0x1950; ++tile) {
        AssignPictToTile(tile);
        UpdateTileNeighborBorderInfluenceCounters(tile, 0);
      }
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventMapEditor), 0);
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
    mapMaker->mapTileGrid08 = static_cast<char*>(static_cast<void*>(terrainStateTable));
    mapMaker->AssignOrCompactCityRegionIdsAndRebuildBorders(1);
  } else if (mapStreamName == 0) {
#ifdef IMPERIALISM_RUNTIME_TESTS
    g_zoneStatusCodePrngSeed_006a5aec = ClockDerivedPrngSeed();
#endif
    if (tuningOverride != 0) {
      CString overrideText(tuningOverride);
      scenarioTagText = overrideText;
    } else {
      GenerateMappedFlavorTextByCurrentContextNation(&scenarioTagText);
    }
    mapMaker->GenerateNewMap(
        static_cast<char*>(static_cast<void*>(terrainStateTable)), cityScoreTable,
        &scenarioTagText);
  }

  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  if (!sessionActive) {
    short tile;
    for (tile = 0; tile < 0x1950; ++tile) {
      UpdateStrategicMapTileIconVariantState(tile);
      TTerrainStateRecord& tileRecord = terrainStateTable[tile];
      tileRecord.formerOwnerNationTag = tileRecord.ownerNationTag04;
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  RebuildTileOwnerNeighborCachesAndFallbackAssignments();
  if (sessionActive) {
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
            SetMapRecordFlagA3AndPropagateToChildren(cityScoreTable[rec].adjacentRegionIds[i],
                                                     classCode);
          }
        }
      }
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  if (!sessionActive) {
    GuaranteeResources();
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  mapMaker->RebuildUMapperRouteRecordsAndActiveMapRects();
  g_pSimMgr->ReinitializeRandomSeed();
  g_zoneStatusCodePrngSeed_006a5aec = 0;
  g_zoneStatusCodePrngSeed_006a5aec = ClockDerivedPrngSeed();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  if (!sessionActive) {
    short tile;
    for (tile = 0; tile < 0x1950; ++tile) {
      AssignPictToTile(tile);
      UpdateTileNeighborBorderInfluenceCounters(tile, 0);
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  g_pViewMgr->RenderTurnEventPalettePreviewSurfaceAndProgress();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  field8 = 1;
  if (mapMaker != 0) {
    mapMaker->Free();
  }
  return 1;
}

// Mac oracle: ReadInRGBMap.
// FUNCTION: IMPERIALISM 0x0050f0e0
void TMapMgr::ReadInRGBMap(const MapPixelSourceView* source) {
  const short* packed = source->packedTiles;
  if (packed == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0x2b0);
  }

  int tileIndex = 0;
  for (int offset = 0; offset < 0x38f40; offset += 0x24) {
    short kindAndRiver = packed[0];
    short ownerAndProvince = packed[1];
    TTerrainStateRecord& record = terrainStateTable[tileIndex];

    record.ownerNationTag04 = static_cast<signed char>(ownerAndProvince);
    packed += 2;
    record.formerOwnerNationTag = record.ownerNationTag04;
    record.terrainKindStorage00 = static_cast<StrategicTerrainKindStorage>(kindAndRiver);
    record.riverSpriteCode = static_cast<RiverSpriteCodeStorage>(kindAndRiver >> 8);

    // Water carries no province; everything else takes the source's high byte.
    if (record.GetTerrainKind() == kStrategicTerrainWater) {
      record.cityRecordIndex = -1;
    } else {
      record.cityRecordIndex = static_cast<ProvinceIndexStorage>(ownerAndProvince >> 8);
    }
    record.tileActionOrdinal = -1;
    record.activeFlags1c = 0;

    UpdateStrategicMapTileIconVariantState(static_cast<StrategicTileIndex>(tileIndex));
    ++tileIndex;
  }

  RebuildTileOwnerNeighborCachesAndFallbackAssignments();
}

// FUNCTION: IMPERIALISM 0x0050f200
void TMapMgr::LoadPoliticalMapRegionSubtypeTableFromResourceStream() {
  CString streamName;
  streamName = "political.map";
  CFile* stream = g_pAssetMgr->LoadTableResourceStreamByName(streamName);
  unsigned char* politicalCodes = new unsigned char[0x1950];
  int byteCount = 0x1950;
  g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, politicalCodes, &byteCount);
  g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);

  int tileIndex = 0;
  for (int recordOffset = 0; recordOffset < 0x38f40; recordOffset += 0x24) {
    short politicalCode = politicalCodes[tileIndex];
    if (politicalCode >= 0x17) {
      terrainStateTable[tileIndex].ownerNationTag04 = static_cast<signed char>(politicalCode);
      terrainStateTable[tileIndex].formerOwnerNationTag = static_cast<signed char>(politicalCode);
      terrainStateTable[tileIndex].SetTerrainKind(kStrategicTerrainWater);
    } else {
      terrainStateTable[tileIndex].SetTerrainKind(kStrategicTerrainPlains);
      terrainStateTable[tileIndex].gateFlag =
          static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(tileIndex));
      terrainStateTable[tileIndex].formerOwnerNationTag = static_cast<signed char>(politicalCode);
      terrainStateTable[tileIndex].ownerNationTag04 = static_cast<signed char>(politicalCode);
      if (politicalCode < 7) {
        terrainStateTable[tileIndex].cityRecordIndex = static_cast<short>(politicalCode << 5);
      } else {
        terrainStateTable[tileIndex].cityRecordIndex = static_cast<short>(politicalCode * 8 + 0xa8);
      }
    }
    ++tileIndex;
  }
}

// FUNCTION: IMPERIALISM 0x0050f3c0
void TMapMgr::VerifyMapDataAndWriteReport() {
  SetCursor(g_pViewMgr->turnEventCursors[0x1a]);

  short* provinceTileCounts = new short[0x180];
  short* pCount = provinceTileCounts;
  for (int i = 0xc0; i != 0; i--) {
    pCount[0] = 0;
    pCount[1] = 0;
    pCount += 2;
  }

  FILE* report = fopen("maperr.txt", s_mcflavor_00697238);
  if (report == NULL) {
    MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0x327);
  }

  fprintf(report, "Map verfication check\n\n");
  int tileIndex = 0;
  do {
    TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
    signed char terrain = tile->terrainKindStorage00;
    if (terrain < 0 || terrain > 7) {
      fprintf(report, "Tile %d bad terrain: %d \n", tileIndex, terrain);
    }
    signed char code = tile->ownerNationTag04;
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      if (code < 0x17) {
        fprintf(report, "Tile %d bad seazone ID: %d \n", tileIndex, code);
      }
      if (tile->cityRecordIndex != -1) {
        fprintf(report, "Tile %d has province ID: %d \n", tileIndex, tile->cityRecordIndex);
      }
    } else {
      if (code > 0x16 || code < 0) {
        fprintf(report, "Tile %d bad country: %d \n", tileIndex, code);
      }
      short provinceId = tile->cityRecordIndex;
      if (provinceId < 0 || provinceId > 0x17f) {
        fprintf(report, "Tile %d bad province: %d \n", tileIndex, provinceId);
      }
      provinceTileCounts[tile->cityRecordIndex]++;
    }
    ++tileIndex;
  } while (tileIndex < 0x1950);

  for (int p = 0; p < 0x180; ++p) {
    if (provinceTileCounts[p] > 0x20) {
      fprintf(report, "Province %d has too many tiles: %d\n", p, provinceTileCounts[p]);
    }
  }

  fprintf(report, "End of verification check\n");
  fclose(report);
  delete[] provinceTileCounts;

  SetCursor(LoadCursorA(NULL, IDC_ARROW));
}

// FUNCTION: IMPERIALISM 0x0050f5f0
void TMapMgr::AssignSequentialClassesToPopulatedRegions() {
  int classCode = 0;
  for (int recordIndex = 0; recordIndex < 0x180; ++recordIndex) {
    Province& record = cityScoreTable[recordIndex];
    if (record.linkedTileIndices42[0] != -1 && record.regionClassA3 == -1) {
      int assignedClass = classCode++;
      if (record.regionClassA3 != assignedClass) {
        record.regionClassA3 = static_cast<char>(assignedClass);
        for (int child = 0; child < record.adjacentRegionCount08; ++child) {
          SetMapRecordFlagA3AndPropagateToChildren(record.adjacentRegionIds[child], assignedClass);
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0050f6b0
void TMapMgr::SetMapRecordFlagA3AndPropagateToChildren(int recordIndex, int classCode) {
  if (cityScoreTable[recordIndex].regionClassA3 != classCode) {
    cityScoreTable[recordIndex].regionClassA3 = static_cast<char>(classCode);
    int i;
    for (i = 0; i < cityScoreTable[recordIndex].adjacentRegionCount08; ++i) {
      SetMapRecordFlagA3AndPropagateToChildren(cityScoreTable[recordIndex].adjacentRegionIds[i],
                                               classCode);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0050f740
void TMapMgr::GenerateProvinceNames() {
  // Hash the scenario tag string to seed the zone status-code PRNG.
  const char* tag = scenarioTagText;
  int seed = kControlTagNada; // "adan"
  while (*tag != '\0') {
    seed = (seed >> 16) + seed * 2 + static_cast<int>(*tag);
    tag++;
  }
  g_zoneStatusCodePrngSeed_006a5aec = seed;
  if (seed == 0) {
    g_zoneStatusCodePrngSeed_006a5aec = ClockDerivedPrngSeed();
  }

  CString local_10;
  AssignNextProvinceNameForNationSlot(&local_10, -1);

  for (int i = 0; i < 0x180; i++) {
    Province* record = &cityScoreTable[i];
    if (record->linkedTileIndices42[0] != -1) {
      AssignNextProvinceNameForNationSlot(&record->cityNameA4, record->ownerNationCode00);
    }
  }

  g_zoneStatusCodePrngSeed_006a5aec = 0;
  g_zoneStatusCodePrngSeed_006a5aec = ClockDerivedPrngSeed();
}

// FUNCTION: IMPERIALISM 0x0050f860
void TMapMgr::RebuildTileOwnerNeighborCachesAndFallbackAssignments() {
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
          bool hasForeignNeighbor = false;
          short neighbors[6];
          GetNeighborTileIDArray(*linkedTile, neighbors, hexNeighborWrapHorizontally);

          int d;
          const short* neighborWalker = neighbors;
          for (d = 6; d != 0; --d) {
            StrategicTileIndex neighborTile = *neighborWalker;
            if (neighborTile != -1) {
              short neighborRec = terrainStateTable[neighborTile].cityRecordIndex;
              if (neighborRec != recIndex && neighborRec != -1) {
                bool inserted = false;
                hasForeignNeighbor = true;
                int k = 0;
                short* slot = record->adjacentRegionIds;
                while (!inserted) {
                  if (*slot == -1) {
                    *slot = neighborRec;
                    inserted = true;
                    slot[0xc] = neighborTile;
                  } else if (*slot == neighborRec) {
                    inserted = true;
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

          if (!hasForeignNeighbor) {
            interiorTiles[interiorCount] = *linkedTile;
            ++interiorCount;
          }

          int edge;
          for (edge = 0; edge < 2; ++edge) {
            char resourceType =
                g_pGlobalMapState->terrainStateTable[*linkedTile].resourceTypeByEdge[edge];
            if (resourceType != -1) {
              record->resourcePresenceMask |= static_cast<unsigned char>(1 << resourceType);
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
      if (record->adjacentRegionIds[0] != -1) {
        for (;;) {
          signed char count = record->adjacentRegionCount08;
          if (count >= 0xc) {
            break;
          }
          ++count;
          record->adjacentRegionCount08 = count;
          if (record->adjacentRegionIds[count] == -1) {
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
                         hexNeighborWrapHorizontally);

  bool consumed[6] = {false, false, false, false, false, false};
  int d;

  int bestDirection = -1;
  short bestPriority = 1;
  for (d = 0; d < 6; ++d) {
    if (neighbors[d] != -1) {
      TTerrainStateRecord* neighbor = &terrainStateTable[neighbors[d]];
      if (neighbor->cityRecordIndex == cityRecordIndex) {
        if (bestPriority < g_anStrategicTerrainNeighborLinkPriority[neighbor->GetTerrainKind()]) {
          bestDirection = d;
          bestPriority = g_anStrategicTerrainNeighborLinkPriority[neighbor->GetTerrainKind()];
        }
      }
    }
  }
  consumed[bestDirection] = true;
  cityScoreTable[cityRecordIndex].primaryNeighborTileIndex = neighbors[bestDirection];

  int secondDirection = -1;
  short secondPriority = -1;
  for (d = 0; d < 6; ++d) {
    if (neighbors[d] != -1 && !consumed[d]) {
      TTerrainStateRecord* neighbor = &terrainStateTable[neighbors[d]];
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
  cityScoreTable[cityRecordIndex].secondaryNeighborTileIndex = neighbors[secondDirection];
}

static const short kHexDirectionBitMask[6] = {1, 2, 4, 8, 16, 32};

static const short kNextHexDirection[6] = {1, 2, 3, 4, 5, 0};

// FUNCTION: IMPERIALISM 0x0050fe10
void TMapMgr::UpdateTileNeighborBorderInfluenceCounters(StrategicTileIndex tileIndex, short mode) {
  short neighbors[6];
  GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally);

  int remainingDirections = 6;
  for (int d = 0; remainingDirections != 0; ++d, --remainingDirections) {
    StrategicTileIndex neighborTile = neighbors[d];
    if (neighborTile == -1) {
      terrainStateTable[tileIndex].ownerBorderMask += kHexDirectionBitMask[d];
      continue;
    }
    if (terrainStateTable[tileIndex].GetTerrainKind() == kStrategicTerrainWater) {
      if (mode == 0 && terrainStateTable[neighborTile].GetTerrainKind() == kStrategicTerrainWater &&
          terrainStateTable[neighborTile].ownerNationTag04 !=
              terrainStateTable[tileIndex].ownerNationTag04) {
        terrainStateTable[tileIndex].ownerBorderMask += kHexDirectionBitMask[d];
      }
    } else if (terrainStateTable[neighborTile].GetTerrainKind() == kStrategicTerrainWater) {
      terrainStateTable[tileIndex].waterAdjacencyMask += kHexDirectionBitMask[d];
    } else {
      if (terrainStateTable[neighborTile].ownerNationTag04 !=
          terrainStateTable[tileIndex].ownerNationTag04) {
        terrainStateTable[tileIndex].ownerBorderMask += kHexDirectionBitMask[d];
      }
      if (mode != 2 && terrainStateTable[neighborTile].cityRecordIndex !=
                           terrainStateTable[tileIndex].cityRecordIndex) {
        terrainStateTable[tileIndex].cityBorderMask += kHexDirectionBitMask[d];
      }
    }
  }

  if (terrainStateTable[tileIndex].GetTerrainKind() == kStrategicTerrainWater) {
    remainingDirections = 6;
    for (int d = 0; remainingDirections != 0; ++d, --remainingDirections) {
      short neighborA = neighbors[d];
      short neighborB = neighbors[kNextHexDirection[d]];
      if (neighborA == -1 || neighborB == -1) {
        continue;
      }
      if (terrainStateTable[neighborA].GetTerrainKind() == kStrategicTerrainWater ||
          terrainStateTable[neighborB].GetTerrainKind() == kStrategicTerrainWater) {
        continue;
      }
      if (terrainStateTable[neighborA].ownerNationTag04 !=
          terrainStateTable[neighborB].ownerNationTag04) {
        terrainStateTable[tileIndex].ownerBorderMask += kHexDirectionBitMask[d];
      }
      if (mode != 2 && terrainStateTable[neighborA].cityRecordIndex !=
                           terrainStateTable[neighborB].cityRecordIndex) {
        terrainStateTable[tileIndex].cityBorderMask += kHexDirectionBitMask[d];
      }
    }
  }

  if (mode != 2) {
    unsigned char cityMask = terrainStateTable[tileIndex].cityBorderMask;
    if ((cityMask & 2) && (cityMask & 1) && neighbors[1] != -1 && neighbors[0] != -1 &&
        terrainStateTable[neighbors[1]].cityRecordIndex !=
            terrainStateTable[neighbors[0]].cityRecordIndex) {
      terrainStateTable[tileIndex].cityBorderMask = cityMask + 0x40;
    }
    cityMask = terrainStateTable[tileIndex].cityBorderMask;
    if ((cityMask & 2) && (cityMask & 4) && neighbors[1] != -1 && neighbors[2] != -1 &&
        terrainStateTable[neighbors[1]].cityRecordIndex !=
            terrainStateTable[neighbors[2]].cityRecordIndex) {
      terrainStateTable[tileIndex].cityBorderMask = cityMask + 0x80;
    }
  }

  unsigned char ownerMask = terrainStateTable[tileIndex].ownerBorderMask;
  if ((ownerMask & 2) && (ownerMask & 1) && neighbors[1] != -1 && neighbors[0] != -1 &&
      terrainStateTable[neighbors[1]].ownerNationTag04 !=
          terrainStateTable[neighbors[0]].ownerNationTag04) {
    terrainStateTable[tileIndex].ownerBorderMask = ownerMask + 0x40;
  }
  ownerMask = terrainStateTable[tileIndex].ownerBorderMask;
  if ((ownerMask & 2) && (ownerMask & 4) && neighbors[1] != -1 && neighbors[2] != -1 &&
      terrainStateTable[neighbors[1]].ownerNationTag04 !=
          terrainStateTable[neighbors[2]].ownerNationTag04) {
    terrainStateTable[tileIndex].ownerBorderMask = ownerMask + 0x80;
  }
}

static const short kOppositeHexDirection[6] = {3, 4, 5, 0, 1, 2};

static void SwapShortBytes(void* value) {
  char* bytes = static_cast<char*>(value);
  char low = bytes[0];
  char high = bytes[1];
  bytes[0] = high;
  bytes[1] = low;
}

// FUNCTION: IMPERIALISM 0x00510210
void TMapMgr::AssignPictToTile(StrategicTileIndex tileIndex) {
  short neighbors[6];

  if (terrainStateTable[tileIndex].GetTerrainKind() != kStrategicTerrainWater) {
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally);
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
      if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
        terrainStateTable[tileIndex].spriteVariantIndex = 1;
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
        terrainStateTable[tileIndex].spriteVariantIndex = 0;
        continue;
      check_pb_nb:
        if (prevTag != 0xb) {
          goto check_next3;
        }
      check_prevb:
        if (terrainStateTable[neighbors[next]].gateFlag != 0xb) {
          goto check_pb2;
        }
        terrainStateTable[tileIndex].spriteVariantIndex = 1;
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
        terrainStateTable[tileIndex].spriteVariantIndex = 2;
        continue;
      check_next3:
        if (terrainStateTable[neighbors[next]].gateFlag != 0xb) {
          continue;
        }
        terrainStateTable[tileIndex].spriteVariantIndex = 3;
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
    if (0x1a < finalVariant && finalVariant < 0x2b) {
      terrainStateTable[tileIndex].riverSpriteCode = finalVariant - 0x10;
      return;
    }
  } else {
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally);
    unsigned int lcg = g_mapGenLcgState_006a38e8;
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] != -1 &&
          terrainStateTable[neighbors[d]].GetTerrainKind() != kStrategicTerrainWater) {
        terrainStateTable[tileIndex].adjacencyMaskB0b |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        lcg = g_mapGenLcgState_006a38e8;
        if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
          terrainStateTable[tileIndex].spriteVariantIndex |=
              (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          lcg = g_mapGenLcgState_006a38e8;
        }
      }
    }
    if (terrainStateTable[tileIndex].adjacencyMaskB0b != 0) {
      RiverSpriteCodeStorage variant = terrainStateTable[tileIndex].riverSpriteCode;
      if (variant == 0) {
        return;
      }
      if ((variant & 0x80) == 0) {
        int resolved = ResolveMapTileVariantSpriteFromAdjacencyState(tileIndex);
        terrainStateTable[tileIndex].riverSpriteCode =
            static_cast<RiverSpriteCodeStorage>(resolved);
        return;
      }
      terrainStateTable[tileIndex].riverSpriteCode = variant & 0x7f;
      return;
    }
    if (neighbors[4] == -1) {
      return;
    }
    if (terrainStateTable[neighbors[4]].spriteVariantIndex != 0) {
      return;
    }
    if (((neighbors[5] == -1) || (terrainStateTable[neighbors[5]].spriteVariantIndex == 0)) &&
        ((neighbors[0] == -1) || (terrainStateTable[neighbors[0]].spriteVariantIndex == 0))) {
      g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
      unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (3 < roll % 100) {
        return;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      terrainStateTable[tileIndex].spriteVariantIndex =
          (unsigned char)((g_mapGenLcgState_006a38e8 >> 0xc) & 3) + 1;
      if (pendingRiverMouthTile != -1) {
        return;
      }
      pendingRiverMouthTile = tileIndex;
      return;
    }
    g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (7 < roll % 100) {
      return;
    }
    char v;
    if (neighbors[5] != -1) {
      v = terrainStateTable[neighbors[5]].spriteVariantIndex;
      if (v != 0) {
        terrainStateTable[tileIndex].spriteVariantIndex = v + 1;
        v = terrainStateTable[tileIndex].spriteVariantIndex;
        if (v != 0) {
          if (v < 5) {
            return;
          }
          terrainStateTable[tileIndex].spriteVariantIndex = 1;
          return;
        }
        goto assign_river_mouth_one;
      }
    }
    if (neighbors[0] != -1) {
      terrainStateTable[tileIndex].spriteVariantIndex =
          terrainStateTable[neighbors[0]].spriteVariantIndex + 1;
      v = terrainStateTable[tileIndex].spriteVariantIndex;
      if ((v == 0) || (4 < v)) {
      assign_river_mouth_one:
        terrainStateTable[tileIndex].spriteVariantIndex = 1;
        return;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005107e0
void TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded(int tileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
  if (tile->gateFlag == 1) {
    return;
  }

  tile->SetTerrainKind(kStrategicTerrainPlains);
  tile->resourceTypeByEdge[0] = -1;
  tile->resourceTypeByEdge[1] = -1;
  tile->resourceTypeByEdge[0] = 0x11;
  tile->gateFlag = static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(tileIndex));

  short neighbors[6];
  GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally);
  for (int d = 0; d < 6; ++d) {
    if (neighbors[d] == -1) {
      continue;
    }
    TTerrainStateRecord* neighbor = &terrainStateTable[neighbors[d]];
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
  TTerrainStateRecord* tiles = terrainStateTable;
  TTerrainStateRecord* cur = &tiles[iTileIndex];
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
      if (!CheckTileVariantCodeMembershipSetB(nTileIndex - 1)) {
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
      if (!CheckTileVariantCodeMembershipSetC(nTileIndex - 0x6b)) {
        if (!CheckTileVariantCodeMembershipSetD(nTileIndex - 0x6b)) {
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
      if (CheckTileVariantCodeMembershipSetA(nTileIndex - 1)) {
        return 0x30;
      }
      if (!CheckTileVariantCodeMembershipSetB(nTileIndex - 1)) {
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
        if (CheckTileVariantCodeMembershipSetA(nTileIndex - 1)) {
          return 0x38;
        }
        if (!CheckTileVariantCodeMembershipSetB(nTileIndex - 1)) {
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
        if (!CheckTileVariantCodeMembershipSetC(nTileIndex - 0x6b)) {
          if (!CheckTileVariantCodeMembershipSetD(nTileIndex - 0x6b)) {
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
                                                           bool waterTerrain) {
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
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
  switch (static_cast<unsigned char>(tile->GetTerrainKind())) {
  case kStrategicTerrainWater: {
    short neighbors[6];
    GetNeighborTileIDArray(tileIndex, neighbors, hexNeighborWrapHorizontally);
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
      TTerrainStateRecord* region = &terrainStateTable[linkedTileIndices[i]];
      for (int edge = 0; edge < 2; ++edge) {
        signed char resourceType = region->resourceTypeByEdge[edge];
        if (resourceType != -1) {
          ++resourceTally[resourceType];
        }
      }
    }

    if (resourceTally[3] == 0) {
      int targetIndex = -1;
      bool found = false;
      do {
        ++targetIndex;
        signed char gateFlag = terrainStateTable[linkedTileIndices[targetIndex]].gateFlag;
        if ((gateFlag == 9 || gateFlag == 8) &&
            terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] == -1) {
          found = true;
        }
      } while (targetIndex < linkedRegionTotal - 1 && !found);

      if (found) {
        terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] = 3;
      } else {
        signed char gateFlag;
        do {
          do {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            targetIndex =
                static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % linkedRegionTotal);
            gateFlag = terrainStateTable[linkedTileIndices[targetIndex]].gateFlag;
          } while (gateFlag == 8);
        } while (gateFlag == 9);
        terrainStateTable[linkedTileIndices[targetIndex]].gateFlag = 8;
        terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] = 3;
      }
      short targetRegion = linkedTileIndices[targetIndex];
      terrainStateTable[targetRegion].resourceTypeByEdge[1] = -1;
      terrainStateTable[targetRegion].gateFlag =
          static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(targetRegion));
    }
    if (resourceTally[4] == 0) {
      int targetIndex = -1;
      bool found = false;
      signed char gateFlag = 0;
      do {
        ++targetIndex;
        gateFlag = terrainStateTable[linkedTileIndices[targetIndex]].gateFlag;
        if ((gateFlag == 9 || gateFlag == 8) &&
            terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] == -1) {
          found = true;
        }
      } while (targetIndex < linkedRegionTotal - 1 && !found);

      if (found) {
        terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] = 4;
        if (gateFlag == 9) {
          terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[1] = -1;
          int resolvedSubtype =
              ResolveRegionTileSubtypeCodeForTileIndex(linkedTileIndices[targetIndex]);
          terrainStateTable[linkedTileIndices[targetIndex]].gateFlag =
              static_cast<signed char>(resolvedSubtype);
          delete[] linkedTileIndices;
          continue;
        }
      } else {
        do {
          do {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            targetIndex =
                static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % linkedRegionTotal);
            gateFlag = terrainStateTable[linkedTileIndices[targetIndex]].gateFlag;
          } while (gateFlag == 8);
        } while (gateFlag == 9);
        terrainStateTable[linkedTileIndices[targetIndex]].gateFlag = 8;
        terrainStateTable[linkedTileIndices[targetIndex]].resourceTypeByEdge[0] = 4;
      }
      short targetRegion = linkedTileIndices[targetIndex];
      terrainStateTable[targetRegion].resourceTypeByEdge[1] = -1;
      terrainStateTable[targetRegion].gateFlag =
          static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(targetRegion));
    }

    delete[] linkedTileIndices;
  }
}

// FUNCTION: IMPERIALISM 0x00511e80
void TMapMgr::TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress() {
  if (field8 == 0) {
    hexNeighborWrapHorizontally = 1;
    BuildOrLoadGlobalMapStateForSession("mapdata", nullptr);
  }
  if (!strategicMapPalettePreviewReady) {
    g_pViewMgr->RenderTurnEventPalettePreviewSurfaceAndProgress();
  }
}

// FUNCTION: IMPERIALISM 0x00511ed0
void TMapMgr::ShowStrategicMapForPlayer() {
  TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress();
  short nationId = g_pSimMgr->GetPlayerCountry();
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventStrategicMap), nationId);
}

// FUNCTION: IMPERIALISM 0x00511f10
short TMapMgr::ComputeRepresentativeTileIndexForNation(int nationSlot) {
  return ComputeRepresentativeTileIndexForNationWithWrapBias(static_cast<short>(nationSlot), true);
}

inline void TMapMgr::MarkOwnedRegionClasses(TLongintList* regionList, bool* regionClassSeen) {
  int ordinal = 1;
  int count = regionList->GetSize();
  while (ordinal <= count) {
    int regionId = regionList->At(ordinal);
    regionClassSeen[cityScoreTable[regionId].regionClassA3] = true;
    ++ordinal;
    count = regionList->GetSize();
  }
}

inline bool TMapMgr::AnyOwnedRegionClassSeen(TLongintList* regionList,
                                             const bool* regionClassSeen) {
  int ordinal = 1;
  int count = regionList->GetSize();
  while (ordinal <= count) {
    int regionId = regionList->At(ordinal);
    if (regionClassSeen[cityScoreTable[regionId].regionClassA3]) {
      return true;
    }
    ++ordinal;
    count = regionList->GetSize();
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00511f30
bool TMapMgr::DoNationTerritoriesShareRegionClass(short nationA, short nationB) {
  bool regionClassSeen[24] = {false};

  int i;
  // Empty ownership lists do not participate in either region-class pass.
  if (g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList->GetSize() >= 1) {
    MarkOwnedRegionClasses(g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList,
                           regionClassSeen);
  }
  for (i = 0; i < 16; ++i) {
    TMinor* minor = g_apNationAuxRuntimeStateSlots[i];
    if (minor != 0 && minor->IsColonyOf(nationA) && minor->ownedRegionList->GetSize() >= 1) {
      MarkOwnedRegionClasses(g_apTerrainTypeDescriptorTable[7 + i]->ownedRegionList,
                             regionClassSeen);
    }
  }

  if (g_apTerrainTypeDescriptorTable[nationB]->ownedRegionList->GetSize() >= 1 &&
      AnyOwnedRegionClassSeen(g_apTerrainTypeDescriptorTable[nationB]->ownedRegionList,
                              regionClassSeen)) {
    return true;
  }
  for (i = 0; i < 16; ++i) {
    TMinor* minor = g_apNationAuxRuntimeStateSlots[i];
    if (minor != 0 && minor->IsColonyOf(nationB) && minor->ownedRegionList->GetSize() >= 1 &&
        AnyOwnedRegionClassSeen(g_apTerrainTypeDescriptorTable[7 + i]->ownedRegionList,
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
    short adjacentRegion = cityScoreTable[cityRecordIndex].adjacentRegionIds[i];
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

// FUNCTION: IMPERIALISM 0x005122f0
int ComputeStrategicHexTileDistance(StrategicTileIndex tileA, StrategicTileIndex tileB) {
  if (tileA == tileB) {
    return 0;
  }

  short rowA = tileA / 0x6c;
  short rasterColumnA = static_cast<short>((rowA % 2) + (tileA % 0x6c) * 2);
  short rowB = tileB / 0x6c;
  short rasterColumnB = static_cast<short>((rowB % 2) + (tileB % 0x6c) * 2);

  if (rasterColumnB < rasterColumnA) {
    rasterColumnB = static_cast<short>(rasterColumnA * 2 - rasterColumnB);
  }
  if (rowB < rowA) {
    rowB = static_cast<short>(rowA * 2 - rowB);
  }

  return (((rasterColumnA + rowB - rasterColumnB - rowA) / 2) - rasterColumnA) + rasterColumnB;
}

// FUNCTION: IMPERIALISM 0x005123e0
int ComputeStridedRecordAddress6C(int recordBase, int recordIndex) {
  return recordBase + recordIndex * 0x6c;
}

// FUNCTION: IMPERIALISM 0x00512410
short* ScaleOffsetsToTilePixelUnits(short a, short b, short* outB, short* outA) {
  *outB = static_cast<short>(b << 6);
  *outA = static_cast<short>(a << 6);
  return outA;
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

// FUNCTION: IMPERIALISM 0x00512850
int ComputeTileIndexFromHexColumnX2AndRow(short columnX2, int row) {
  return columnX2 / 2 + row * 0x6c;
}

// Dead coordinate helper: copies `b` to `outCopy` and stores/returns `a` halved.
// FUNCTION: IMPERIALISM 0x00512880
int CopyOffsetAndHalve(short a, short b, short* outHalf, short* outCopy) {
  *outCopy = b;
  *outHalf = static_cast<short>(a / 2);
  return a / 2;
}

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
  int rowParity = row % 2;
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
  int rowParity = row % 2;
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
  short diagFrom = static_cast<short>((rowFrom % 2) + colFrom * 2);
  short rowTo = destTile / 0x6c;
  short colTo = destTile % 0x6c;
  short diagTo = static_cast<short>((rowTo % 2) + colTo * 2);

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
    if (town->tileIndex == tileIndex) {
      return town;
    }
  }
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00513200
void TMapMgr::SetTileTransportFlags(StrategicTileIndex nTileIndex,
                                    unsigned short wTileTransportFlags) {
  TTerrainStateRecord* tile = &terrainStateTable[nTileIndex];
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
}

const int kGlobalMapTileCount = 0x1950;

// FUNCTION: IMPERIALISM 0x00513290
void TMapMgr::ChangeProvinceOwner(ProvinceIndexStorage cityRecordIndex, short newNationTag) {
  Province* city = &cityScoreTable[cityRecordIndex];
  signed char oldNationCode = city->ownerNationCode00;

  for (int i = 0; i < city->linkedRegionCount; ++i) {
    SetOwner(city->linkedTileIndices42[i], newNationTag);
  }

  city->ownerNationCode00 = static_cast<signed char>(newNationTag);
  g_apTerrainTypeDescriptorTable[oldNationCode]->LoseProvince(cityRecordIndex);
  g_apTerrainTypeDescriptorTable[newNationTag]->AddProvince(cityRecordIndex);
  g_pMapContextActionManager->perTileOwnerNationCodeCache1c[cityRecordIndex] =
      static_cast<short>(newNationTag);

  bool isPrimary = g_pDiplomacyTurnStateManager->IsGreatPower(newNationTag);
  if (isPrimary && g_pSimMgr->multiplayerSessionRole != kSessionRoleClient) {
    g_apNationStates[newNationTag]->AddNoticeFrom(oldNationCode, 0x135);
  }
  if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
    g_pGameFlowState->SendChangeProvinceOwner(cityRecordIndex, newNationTag);
  }
}

// FUNCTION: IMPERIALISM 0x005133f0
void TMapMgr::SetOwner(short regionId, short newNationTag) {
  signed char oldOwner = terrainStateTable[regionId].ownerNationTag04;
  if (oldOwner == newNationTag) {
    return;
  }

  terrainStateTable[regionId].ownerNationTag04 = static_cast<signed char>(newNationTag);
  terrainStateTable[regionId].ownerBorderMask = 0;
  UpdateTileNeighborBorderInfluenceCounters(regionId, 2);

  short neighbors[6];
  GetNeighborTileIDArray(regionId, neighbors, hexNeighborWrapHorizontally);
  for (int d = 0; d < 6; ++d) {
    if (neighbors[d] != -1) {
      terrainStateTable[neighbors[d]].ownerBorderMask = 0;
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
      if (matchedTown->tileIndex == regionId) {
        found = true;
        break;
      }
      ++ordinal;
      count = oldTownList->GetCount();
    }
    if (found) {
      oldTownList->RemoveAtOrdinal(ordinal);
      matchedTown->ownerNation = newNationTag;
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
  signed char raw = terrainStateTable[tileIndex].developmentClassNibbles;
  signed char index = g_abResourceTypeUsesHighNibbleFlag[resourceType] != 0 ? (raw >> 4) : raw;
  return g_abUniversityRequirementLevelById[resourceType][index];
}

// FUNCTION: IMPERIALISM 0x00513660
char TMapMgr::GetTileCivilianWorkOrderCostClassNibble(StrategicTileIndex nTileIndex,
                                                      bool fUseHighNibble) {
  if (fUseHighNibble) {
    char costClass = terrainStateTable[nTileIndex].developmentClassNibbles;
    costClass >>= 4;
    return costClass;
  }
  char costClass = terrainStateTable[nTileIndex].developmentClassNibbles;
  costClass &= 0xf;
  return costClass;
}

// FUNCTION: IMPERIALISM 0x005136a0
void TMapMgr::SetDevelopmentLevel(StrategicTileIndex tileIndex, bool selectHighNibble,
                                                byte value, bool markPending) {
  unsigned char packed = terrainStateTable[tileIndex].developmentClassNibbles;
  if (selectHighNibble) {
    packed = (packed & 0xf) | (value << 4);
  } else {
    packed = (packed & 0xf0) | value;
  }
  terrainStateTable[tileIndex].developmentClassNibbles = packed;
  if (selectHighNibble) {
    if (static_cast<signed char>(value) > 0 && markPending) {
      terrainStateTable[tileIndex].pendingDevelopmentFlag = 0x7f;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00513720
short TMapMgr::GetMaxDevelopmentLevel(StrategicTileIndex tileIndex,
                                                     char categoryCode, int nationSlot) {
  signed char* resourceTypeSlot = terrainStateTable[tileIndex].resourceTypeByEdge;
  short maxValue = 0;
  int remainingSlots = 2;
  do {
    short resourceType = *resourceTypeSlot;
    if (resourceType != -1 && g_abResourceTypeCapabilityCategory[resourceType] == categoryCode) {
      short value = g_pTechMgr->capabilityValueByNationAndResource[nationSlot][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    ++resourceTypeSlot;
    --remainingSlots;
  } while (remainingSlots != 0);
  return maxValue;
}

// FUNCTION: IMPERIALISM 0x005137b0
char TMapMgr::CanBuildPortAtTile(StrategicTileIndex tileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
  bool result = false;
  if (tile->GetTerrainKind() != kStrategicTerrainMountain &&
      tile->GetTerrainKind() != kStrategicTerrainHills) {
    int row = tileIndex / 0x6c;
    int col = tileIndex % 0x6c;
    for (short direction = 0; direction < 6; ++direction) {
      int scaledCol = row % 2 + col * 2 + g_Build_Hex_Area_LookupTable_00696E70[direction];
      int neighborRow = row + g_Build_Hex_Area_LookupTable_00696E80[direction];
      if (scaledCol < 0) {
        scaledCol += 0xd8;
      } else if (scaledCol >= 0xd8) {
        scaledCol -= 0xd9;
      }
      if (neighborRow < 0) {
        neighborRow = 0;
      } else if (neighborRow > 0x3b) {
        neighborRow = 0x3b;
      }
      short neighbor = static_cast<short>(scaledCol / 2 + neighborRow * 0x6c);
      if (neighbor < 0 || neighbor >= 0x1950) {
        neighbor = -1;
      }
      if (neighbor != -1 &&
          terrainStateTable[neighbor].GetTerrainKind() == kStrategicTerrainWater) {
        result = true;
        break;
      }
    }
  }
  if (!result && tile->riverSpriteCode != kRiverSpriteCodeNone &&
      EvaluateTerrainFlowCrossNationBoundaryToSea(tileIndex) == 0) {
    result = true;
  }
  return result;
}
// FUNCTION: IMPERIALISM 0x00513980
bool TMapMgr::IsValidSecondaryNationHomeTileCandidate(StrategicTileIndex tileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
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

// FUNCTION: IMPERIALISM 0x00513ca0
char TMapMgr::HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(StrategicTileIndex tileIndex) {
  int originNation = static_cast<signed char>(terrainStateTable[tileIndex].ownerNationTag04);
  bool result = false;
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
        result = true;
      }
      break;
    }
  }

  if (!result &&
      g_pGlobalMapState->terrainStateTable[tileIndex].riverSpriteCode != kRiverSpriteCodeNone &&
      EvaluateTerrainFlowCrossNationBoundaryToSea(tileIndex) == 0) {
    short seaTile = TraceTerrainFlowToNearestSeaTile(tileIndex);
    short seaNation = terrainStateTable[seaTile].ownerNationTag04;
    if (g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(seaNation)
            ->HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask(originNation) == 0) {
      result = true;
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
            (g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] != '\0')))) {
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
  terrainStateTable[sourceTile].railFlags += g_railDirectionAddMasks_00696eb8[dir];
  terrainStateTable[destTile].railFlags += g_railDirectionAddMasks_00696eb8[(dir + 3) % 6];
}

// FUNCTION: IMPERIALISM 0x00514080
void TMapMgr::ApplyEngineerRailCostDeltaForConnectedTiles(StrategicTileIndex tileA,
                                                          StrategicTileIndex tileB,
                                                          short ownerNation) {
  (void)ownerNation;
  short dir = GetDirectionFrom(tileA, tileB);
  terrainStateTable[tileA].railFlags -= g_railDirectionSubtractMasks_00696ec8[dir];
  terrainStateTable[tileB].railFlags -= g_railDirectionSubtractMasks_00696ec8[(dir + 3) % 6];
}

// FUNCTION: IMPERIALISM 0x00514110
short TMapMgr::ResolveRegionTileSubtypeCodeForTileIndex(StrategicTileIndex tileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
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
  while ((entry != nullptr) && (entry->ownerNationSlot18 != nationId)) {
    entry = static_cast<TCivUnit*>(entry->nextAtLocation);
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
  if (nation->encodedNationSlot < 200) {
    return ownerCode;
  }
  short code = nation->encodedNationSlot;
  if (code < 200) {
    if (code < 100) {
      return nation->nationSlot;
    }
    return code - 100;
  }
  return code - 200;
}

// FUNCTION: IMPERIALISM 0x00514310
bool TMapMgr::HasCivilianUnitKind(StrategicTileIndex tileIndex, CivilianUnitKindStorage unitKind) {
  for (TCivUnit* order = terrainStateTable[tileIndex].firstCivilianOrder20; order != nullptr;
       order = static_cast<TCivUnit*>(order->nextAtLocation)) {
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
       order = static_cast<TCivUnit*>(order->nextAtLocation)) {
    if (order->orderType == unitKind && order->unitOrder == DecodeUnitOrder(orderValue)) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005143d0
void TMapMgr::FloodFillTileRegionMarker(StrategicTileIndex nTileIndex, short nOwnerNationId) {
  unsigned char regionMarkerId = static_cast<unsigned char>(g_nNextRegionMarkerId);
  terrainStateTable[nTileIndex].regionSubtypeTag = regionMarkerId;

  if (terrainStateTable[nTileIndex].activeFlags1c & 2) {
    short cityIdx = terrainStateTable[nTileIndex].cityRecordIndex;
    if (cityScoreTable[cityIdx].lastTurnTick == 999) {
      cityScoreTable[cityIdx].lastTurnTick = g_pSimMgr->GetEconomicTurn();
    }
  }

  short neighbors[6];
  GetNeighborTileIDArray(nTileIndex, neighbors, hexNeighborWrapHorizontally);
  for (int d = 0; d < 6; ++d) {
    StrategicTileIndex neighborTile = neighbors[d];
    if (neighborTile == -1) {
      continue;
    }
    if (terrainStateTable[neighborTile].ownerNationTag04 != nOwnerNationId) {
      continue;
    }
    if (terrainStateTable[neighborTile].regionSubtypeTag != -1) {
      continue;
    }

    terrainStateTable[neighborTile].regionSubtypeTag = regionMarkerId;
    if (terrainStateTable[neighborTile].activeFlags1c & 2) {
      short cityIdx = terrainStateTable[neighborTile].cityRecordIndex;
      bool skipRedraw = false;
      if (cityScoreTable[cityIdx].lastTurnTick == 999) {
        cityScoreTable[cityIdx].lastTurnTick = g_pSimMgr->GetEconomicTurn();
        if (g_nSaveFormatVersion == -3) {
          skipRedraw = true;
        } else if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
          g_pGameFlowState->DispatchCityRedrawInvalidateEvent(cityIdx);
        }
      }
      if (!skipRedraw && g_nSaveFormatVersion != -3 &&
          g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
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
    town->activeFlag = true;
  } else {
    town = new TTown();
    town->ITown(static_cast<LPCSTR>(emptyName), nTileIndex, false, nNationId);

    TSortedList* townMarkers = g_apNationStates[nNationId]->townMarkerList;
    if (townMarkers == 0) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMap.cpp", 0xfa8);
    }
    townMarkers->AddTail(town);
    FloodFillTileRegionMarker(nTileIndex, nNationId);
  }

  TGreatPower* nation = g_apNationStates[nNationId];
  if (nation->diplomacyEligibility == 0) {
    nation->treasuryValue10 -= 2000;
  }
  terrainStateTable[nTileIndex].activeFlags1c |= 0x10;

  if (g_nSaveFormatVersion != -3 && g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->SendStreamObject(kControlTagTown, town, -2);
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
    town->enabledFlag = true;
  } else {
    town = new TTown();
    town->ITown(g_szEmptyString, nTileIndex, true, nNationId);

    TSortedList* townMarkers = g_apNationStates[nNationId]->townMarkerList;
    if (townMarkers == 0) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMap.cpp", 0xfda);
    }
    townMarkers->AddTail(town);
    FloodFillTileRegionMarker(nTileIndex, nNationId);
  }

  TGreatPower* nation = g_apNationStates[nNationId];
  if (nation->diplomacyEligibility == 0) {
    nation->treasuryValue10 -= 3000;
  }
  terrainStateTable[nTileIndex].activeFlags1c |= 4;
  g_pActiveMapOrderContext->EnsurePortZoneForTile(nTileIndex);

  if (g_nSaveFormatVersion != -3 && g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pGameFlowState->SendStreamObject(kControlTagTown, town, -2);
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
void TMapMgr::PlaceCity(StrategicTileIndex nTileIndex, short nOwnerNationId) {
  short cityRecordIndex = terrainStateTable[nTileIndex].cityRecordIndex;
  SetRegionTileSubtypeAndRefreshNeighborFlags(cityRecordIndex, nTileIndex);

  terrainStateTable[nTileIndex].activeFlags1c = 0x17;
  terrainStateTable[nTileIndex].activeFlags1c |= 0x20;
  FloodFillTileRegionMarker(nTileIndex, nOwnerNationId);

  signed char originRegionTag = terrainStateTable[nTileIndex].regionSubtypeTag;
  for (int direction = 0; direction <= 6; ++direction) {
    StrategicTileIndex neighborTile;
    if (direction == 6) {
      neighborTile = nTileIndex;
    } else {
      int row = nTileIndex / 0x6c;
      int scaledColumn =
          row % 2 + (nTileIndex % 0x6c) * 2 + g_Build_Hex_Area_LookupTable_00696E70[direction];
      int neighborRow = row + g_Build_Hex_Area_LookupTable_00696E80[direction];
      if (scaledColumn < 0) {
        scaledColumn += 0xd8;
      } else if (scaledColumn >= 0xd8) {
        scaledColumn -= 0xd9;
      }
      if (neighborRow < 0) {
        neighborRow = 0;
      } else if (neighborRow > 0x3b) {
        neighborRow = 0x3b;
      }
      neighborTile = static_cast<short>(scaledColumn / 2 + neighborRow * 0x6c);
      if (neighborTile < 0 || neighborTile >= 0x1950) {
        neighborTile = -1;
      }
    }
    if (neighborTile == -1) {
      continue;
    }
    TTerrainStateRecord* neighbor = &terrainStateTable[neighborTile];
    if (neighbor->regionSubtypeTag != originRegionTag) {
      continue;
    }

    bool eligible = false;
    for (int edge = 0; edge < 2; ++edge) {
      signed char resourceType = neighbor->resourceTypeByEdge[edge];
      if ((resourceType == kResourceGrain || resourceType == kResourceFruit) &&
          g_abGateFlagQualifies[neighbor->gateFlag] != 0) {
        eligible = true;
      }
    }
    if (eligible) {
      SetDevelopmentLevel(neighborTile, false, 1, true);
    }
  }

  g_pActiveMapOrderContext->EnsurePortZoneForTile(nTileIndex);
  terrainStateTable[nTileIndex].gateFlag =
      static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(nTileIndex));
}

// FUNCTION: IMPERIALISM 0x00514c80
StrategicTileIndex
TMapMgr::FindReachableRecruitSpawnTileWithVisitedReset(StrategicTileIndex startTileIndex,
                                                       bool allowActiveFlag2) {
  signed char ownerNationTag = terrainStateTable[startTileIndex].ownerNationTag04;
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  return SearchOpenTile(startTileIndex, ownerNationTag, allowActiveFlag2);
}

// FUNCTION: IMPERIALISM 0x00514cd0
StrategicTileIndex TMapMgr::SearchOpenTile(StrategicTileIndex tileIndex,
                                                                   short ownerNationTag,
                                                                   bool allowActiveFlag2) {
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
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
    while (civilianOrder->ownerNationSlot18 != ownerNationTag) {
      civilianOrder = civilianOrder->nextAtLocation;
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
    if (allowActiveFlag2) {
      return tileIndex;
    }
  }

  StrategicTileIndex neighborTiles[6];
  GetNeighborTileIDArray(tileIndex, neighborTiles, hexNeighborWrapHorizontally);
  for (short neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    if (neighborTiles[neighborIndex] == -1) {
      continue;
    }
    StrategicTileIndex foundTile = SearchOpenTile(
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
    TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
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
  TTerrainStateRecord* tile = terrainStateTable;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex, ++tile) {
    tile->recruitSearchVisited0e = (tile->ownerNationTag04 != ownerNationTag) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00514e80
void TMapMgr::SeedRecruitSearchVisitedStateFromSelectedCivilianOrder(TCivUnit* unusedOrder) {
  (void)unusedOrder;
  TTerrainStateRecord* tile = terrainStateTable;
  this->field9 = 1;
  for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex, ++tile) {
    TCivUnit* selectedEntry = g_pSelectedCivilianOrderState->selectedEntry;
    if (selectedEntry == nullptr) {
      continue;
    }
    if (selectedEntry->tileIndex06 == tileIndex) {
      tile->recruitSearchVisited0e = (terrainStateTable[tileIndex].activeFlags1c >> 4) & 1;
    } else {
      tile->recruitSearchVisited0e = 1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00514ef0
void TMapMgr::ResetRecruitSearchVisitedState() {
  TTerrainStateRecord* tile = terrainStateTable;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex, ++tile) {
    tile->recruitSearchVisited0e = 0;
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

  if (pCivilianOrderEntry->orderType != EncodeCivilianUnitKind(kCivilianUnitProspector) &&
      pCivilianOrderEntry->orderType != EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
    return;
  }
  if (pCivilianOrderEntry->militaryRegistrationFlag != 0) {
    return;
  }

  TTerrainStateRecord* refTile = &terrainStateTable[refTileIndex];
  unsigned char flags = refTile->activeFlags1c;
  bool gateFlagPasses = (flags & 3) != 0 && refTile->gateFlag != 0;
  if (!gateFlagPasses && (flags & 4) == 0) {
    return;
  }

  if (refOwner == pCivilianOrderEntry->ownerNationSlot18) {
    TTown* town = FindTownMarkerForTileByOwnerNation(refTileIndex);
    if (town->enabledFlag == 0) {
      return;
    }
  }

  for (int minorSlot = 7; minorSlot < 23; ++minorSlot) {
    TCountry* minorObj = g_apTerrainTypeDescriptorTable[minorSlot];
    if (minorObj == nullptr) {
      continue;
    }
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(minorSlot,
                                                        pCivilianOrderEntry->ownerNationSlot18)) {
      continue;
    }
    terrainStateTable[static_cast<short>(minorObj->homeTileIndex)].recruitSearchVisited0e = 0;
  }

  TGreatPower* owner = g_apNationStates[pCivilianOrderEntry->ownerNationSlot18];
  TSortedList* townMarkerList = owner->townMarkerList;
  for (int ordinal = 1; ordinal <= townMarkerList->GetCount(); ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->enabledFlag != 0) {
      terrainStateTable[town->tileIndex].recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005150e0
void TMapMgr::DimByMarching(
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

  short nationSlot = unit->ownerNationSlot18;
  field9 = 1;
  int tileScanIndex;
  for (tileScanIndex = 0; tileScanIndex < 0x1950; ++tileScanIndex) {
    terrainStateTable[tileScanIndex].recruitSearchVisited0e = 1;
  }
  terrainStateTable[unit->tileIndex06].recruitSearchVisited0e = 0;

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
    targetTileIndex = unit->orderTargetTiles[orderTargetSlot - 1];
  } else {
    targetTileIndex = unit->tileIndex06;
  }

  for (short direction = 0; direction < 6; ++direction) {
    int row = targetTileIndex / 0x6c;
    int scaledColumn =
        row % 2 + (targetTileIndex % 0x6c) * 2 + g_Build_Hex_Area_LookupTable_00696E70[direction];
    int neighborRow = row + g_Build_Hex_Area_LookupTable_00696E80[direction];
    if (scaledColumn < 0) {
      scaledColumn += 0xd8;
    } else if (scaledColumn >= 0xd8) {
      scaledColumn -= 0xd9;
    }
    if (neighborRow < 0) {
      neighborRow = 0;
    } else if (neighborRow > 0x3b) {
      neighborRow = 0x3b;
    }
    StrategicTileIndex neighborTile = static_cast<short>(scaledColumn / 2 + neighborRow * 0x6c);
    if (neighborTile < 0 || neighborTile >= 0x1950) {
      neighborTile = -1;
    }
    if (neighborTile == -1) {
      continue;
    }
    TTerrainStateRecord* neighbor = &terrainStateTable[neighborTile];
    if (neighbor->ownerNationTag04 == nationSlot) {
      neighbor->recruitSearchVisited0e = 0;
    } else if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(neighbor->ownerNationTag04,
                                                               nationSlot)) {
      neighbor->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00515330
void TMapMgr::DimByProspecting(TCivUnit* pCivilianOrderEntry) {
  field9 = 1;
  short nationTag = pCivilianOrderEntry->ownerNationSlot18;
  unsigned char eligibleGateFlags[24] = {0};
  eligibleGateFlags[8] = 1;
  eligibleGateFlags[9] = 1;
  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x13] == 2) {
    eligibleGateFlags[10] = 1;
    eligibleGateFlags[11] = 1;
    eligibleGateFlags[12] = 1;
  }
  unsigned char nationBit = 1 << nationTag;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->ownerNationTag04 != nationTag) {
      if (tile->ownerNationTag04 < 7) {
        tile->recruitSearchVisited0e = 1;
        continue;
      }
      if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(
              nationTag, tile->ownerNationTag04) != 2) {
        tile->recruitSearchVisited0e = 1;
        continue;
      }
    }
    if (eligibleGateFlags[tile->gateFlag] == 0) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    tile->recruitSearchVisited0e = (nationBit & tile->pendingDevelopmentFlag) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515460
void TMapMgr::DimByDevelopment(TCivUnit* pCivilianOrderEntry) {
  short nationTag = pCivilianOrderEntry->ownerNationSlot18;
  bool recruitTierFlagIsTwo =
      (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x13] == 2);
  field9 = 1;
  unsigned char nationBit = 1 << nationTag;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
    tile->recruitSearchVisited0e = 1;
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      continue;
    }
    if (tile->ownerNationTag04 < 7) {
      continue;
    }
    if (g_pDiplomacyTurnStateManager->GetEmbassyStatus(
            nationTag, tile->ownerNationTag04) != 2) {
      continue;
    }
    if (tile->secondaryOwnerNationTag != -1) {
      continue;
    }
    if (g_abGateFlagQualifies[tile->gateFlag] == 0) {
      continue;
    }
    bool found = false;
    for (int edge = 0; edge < 2; ++edge) {
      signed char resourceType = tile->resourceTypeByEdge[edge];
      if (resourceType == kResourceCotton || resourceType == kResourceWool ||
          resourceType == kResourceTimber) {
        found = true;
        continue;
      }
      if (tile->pendingDevelopmentFlag & nationBit) {
        if (resourceType == kResourceCoal || resourceType == kResourceIron ||
            resourceType == kResourceGems || resourceType == kResourceGold) {
          found = true;
        } else if (recruitTierFlagIsTwo && resourceType == kResourceOil) {
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
void TMapMgr::DimByMining(TCivUnit* pCivilianOrderEntry) {
  unsigned char qualifiesByResourceType[23] = {0};
  if (pCivilianOrderEntry->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner)) {
    qualifiesByResourceType[3] = 1;
    qualifiesByResourceType[4] = 1;
    qualifiesByResourceType[21] = 1;
    qualifiesByResourceType[22] = 1;
  } else {
    qualifiesByResourceType[6] = 1;
  }

  this->field9 = 1;
  short nationTag = pCivilianOrderEntry->ownerNationSlot18;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
    if (tile->GetTerrainKind() == kStrategicTerrainWater) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->ownerNationTag04 != nationTag && tile->secondaryOwnerNationTag != nationTag) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->pendingDevelopmentFlag == 0) {
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
      short value = g_pTechMgr->capabilityValueByNationAndResource[nationTag][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    signed char highNibble = tile->developmentClassNibbles >> 4;
    tile->recruitSearchVisited0e = (highNibble >= maxValue) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515720
void TMapMgr::DimByFishing(TCivUnit* pCivilianOrderEntry) {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 1;
  }

  short nationTag = pCivilianOrderEntry->ownerNationSlot18;
  TGreatPower* nation = g_apNationStates[nationTag];
  TSortedList* townMarkerList = nation->townMarkerList;
  for (int ordinal = 1; ordinal <= townMarkerList->GetCount(); ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->enabledFlag == 0) {
      continue;
    }
    short regionId = town->tileIndex;
    signed char townTag5 = terrainStateTable[regionId].regionSubtypeTag;
    short neighbors[6];
    GetNeighborTileIDArray(regionId, neighbors, hexNeighborWrapHorizontally);
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] == -1) {
        continue;
      }
      TTerrainStateRecord* neighbor = &terrainStateTable[neighbors[d]];
      if (neighbor->GetTerrainKind() != kStrategicTerrainWater) {
        continue;
      }
      if (neighbor->regionSubtypeTag != townTag5) {
        continue;
      }
      if (neighbor->developmentClassNibbles <
          g_pTechMgr->capabilityValueByNationAndResource[nationTag][19]) {
        neighbor->recruitSearchVisited0e = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00515890
void TMapMgr::DimByCompany(TCivUnit* pCivilianOrderEntry) {
  this->field9 = 1;
  short nationTag = pCivilianOrderEntry->ownerNationSlot18;
  short orderType = pCivilianOrderEntry->orderType;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
    tile->recruitSearchVisited0e = 1;
    if (tile->ownerNationTag04 != nationTag && tile->secondaryOwnerNationTag != nationTag) {
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
      short value = g_pTechMgr->capabilityValueByNationAndResource[nationTag][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    signed char lowNibble = tile->developmentClassNibbles & 0xf;
    if (lowNibble < maxValue) {
      tile->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005159b0
void TMapMgr::DimByTrackLaying(TCivUnit* pCivilianOrderEntry) {
  this->field9 = 1;
  for (int i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].recruitSearchVisited0e = 1;
  }

  short nationTag = pCivilianOrderEntry->ownerNationSlot18;
  StrategicTileIndex tileIndex = pCivilianOrderEntry->tileIndex06;

  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x06] == 2) {
    g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainSwamp] = 1;
  }
  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x0c] == 2) {
    g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainHills] = 1;
  }
  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x17] == 2) {
    g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainMountain] = 1;
  }

  if (g_abStrategicTerrainSeedGateProfileA[terrainStateTable[tileIndex].GetTerrainKind()] != 0) {
    StrategicTileIndex* neighbors = BuildHexAreaTileIndexList(tileIndex, 1);
    unsigned char directionBit = 0;
    for (int d = 0; d < 6; ++d) {
      TTerrainStateRecord* neighbor = &terrainStateTable[neighbors[d]];
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
void TMapMgr::DimByEngineering(TCivUnit* pCivilianOrderEntry) {
  StrategicTileIndex tileIndex = pCivilianOrderEntry->tileIndex06;
  short nationTag = pCivilianOrderEntry->ownerNationSlot18;

  unsigned char terrainKindGate[kStrategicTerrainCount] = {1, 1, 0, 0, 0, 0, 1, 1};
  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x06] == 2) {
    terrainKindGate[kStrategicTerrainSwamp] = 1;
    terrainKindGate[kStrategicTerrainWater] = 0;
    terrainKindGate[kStrategicTerrainDesert] = 1;
    terrainKindGate[kStrategicTerrainFarmland] = 1;
  }
  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x0c] == 2) {
    terrainKindGate[kStrategicTerrainPlains] = 1;
    terrainKindGate[kStrategicTerrainForest] = 1;
    terrainKindGate[kStrategicTerrainHills] = 1;
    terrainKindGate[kStrategicTerrainMountain] = 0;
  }
  if (g_pTechMgr->orderCapRows277[nationTag].techStatusByTechId[0x17] == 2) {
    terrainKindGate[kStrategicTerrainMountain] = 1;
  }

  this->field9 = 1;
  for (int i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].recruitSearchVisited0e = 1;
  }

  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
  if (terrainKindGate[tile->GetTerrainKind()] != 0) {
    if (tile->regionSubtypeTag == -1 || cityScoreTable[tile->cityRecordIndex].fortLevel03 < 3) {
      tile->recruitSearchVisited0e = 0;
    }

    StrategicTileIndex* neighbors = BuildHexAreaTileIndexList(tileIndex, 1);
    unsigned char directionBit = 0;
    for (int d = 0; d < 6; ++d) {
      TTerrainStateRecord* neighbor = &terrainStateTable[neighbors[d]];
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
    g_pMapContextActionManager->AnySelectableUnits(static_cast<short>(tileIndex));
  }
}

// FUNCTION: IMPERIALISM 0x00515db0
void TMapMgr::DimmingOff() {
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].perTileVisitedFlag = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515de0
void TMapMgr::NoOpVirtualSlot2D(int, int, int) {
}

// FUNCTION: IMPERIALISM 0x00515e00
void TMapMgr::SetMapTileStateByteAndNotifyObserver(StrategicTileIndex tileIndex, int stateByte) {
  terrainStateTable[tileIndex].tileActionState16 =
      static_cast<MapTileActionStateStorage>(stateByte);
  if (g_pViewMgr->mapUberPictureF0 != 0) {
    g_pViewMgr->mapUberPictureF0->InvalidateTile(tileIndex);
  }
}

// FUNCTION: IMPERIALISM 0x00515e50
char TMapMgr::IsProvinceAdjacentTo(int sourceProvinceIndex, int candidateProvinceIndex) {
  const Province& record = cityScoreTable[sourceProvinceIndex];
  for (int i = 0; i < record.adjacentRegionCount08; ++i) {
    if (record.adjacentRegionIds[i] == candidateProvinceIndex) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00515ec0
void TMapMgr::AssignCityRecordDisplayName(ProvinceIndex cityRecordIndex, CString* dest) {
  *dest = cityScoreTable[cityRecordIndex].cityNameA4;
}

// FUNCTION: IMPERIALISM 0x00515f00
void TMapMgr::GetProvinceName(int provinceIndex, CString* outName) {
  *outName = cityScoreTable[provinceIndex].cityNameA4;
}

// FUNCTION: IMPERIALISM 0x00515f40
void TMapMgr::SetGlobalMapCellSharedLabel(ProvinceIndex cityRecordIndex, CString* name) {
  cityScoreTable[cityRecordIndex].cityNameA4 = *name;
}

// FUNCTION: IMPERIALISM 0x00515f80
void TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags(ProvinceIndex cityRecordIndex,
                                                          int newTileIndex) {
  Province* city = &cityScoreTable[cityRecordIndex];

  int oldTileIndex = city->cityTileIndex04;
  if (oldTileIndex != -1) {
    TTerrainStateRecord* oldTile = &terrainStateTable[oldTileIndex];
    oldTile->activeFlags1c = 0;
    oldTile->gateFlag =
        static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(oldTileIndex));
    oldTile->resourceTypeByEdge[0] = 0x11;
  }

  TTerrainStateRecord* newTile = &terrainStateTable[newTileIndex];
  newTile->activeFlags1c = 2;
  city->cityTileIndex04 = newTileIndex;
  newTile->activeFlags1c |= 0x20;
  newTile->gateFlag =
      static_cast<signed char>(ResolveRegionTileSubtypeCodeForTileIndex(newTileIndex));

  for (int i = 0; i < city->linkedRegionCount; ++i) {
    TTerrainStateRecord* linkedTile = &terrainStateTable[city->linkedTileIndices42[i]];
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
    if (city->adjacentRegionIds[i] == regionId) {
      return city->adjacentRegionAnchorTiles[i];
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00516100
void TMapMgr::SetCapitalCityDevelopmentStageIfValidNationSlot(int nation, int unused) {
  (void)unused;
  short capitalTileIndex =
      static_cast<short>(g_apTerrainTypeDescriptorTable[nation]->homeTileIndex);
  short cityRecordIndex = terrainStateTable[capitalTileIndex].cityRecordIndex;
  if (nation < 7) {
    cityScoreTable[cityRecordIndex].developmentStage = 2;
  }
}

// FUNCTION: IMPERIALISM 0x00516150
short TMapMgr::LookupTileSpriteVariantOffsetByTerrainAndGate(StrategicTileIndex nTileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[nTileIndex];
  if (tile->GetTerrainKind() == kStrategicTerrainMountain) {
    return g_awTileSpriteVariantOffsetTable38[tile->gateFlag][tile->spriteVariantIndex];
  }
  return g_awTileSpriteVariantOffsetTable38[tile->gateFlag][0];
}

// FUNCTION: IMPERIALISM 0x005161a0
short TMapMgr::LookupTileSpriteVariantOffsetByAdjacencyMaskB(StrategicTileIndex nTileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[nTileIndex];
  if (tile->adjacencyMaskB0b != 0) {
    return g_awTileSpriteVariantOffsetTable39[0];
  }
  return g_awTileSpriteVariantOffsetTable39[tile->spriteVariantIndex];
}

// FUNCTION: IMPERIALISM 0x005161e0
short TMapMgr::LookupTileSpriteVariantOffsetByGateAndVariant(StrategicTileIndex nTileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[nTileIndex];
  return g_awTileSpriteVariantOffsetTable3a[tile->gateFlag][tile->spriteVariantIndex];
}

// FUNCTION: IMPERIALISM 0x00516220
short TMapMgr::LookupTileSpriteVariantOffsetByGateAndVariantAlt(StrategicTileIndex nTileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[nTileIndex];
  return g_awTileSpriteVariantOffsetTable3b[tile->gateFlag][tile->spriteVariantIndex];
}

// FUNCTION: IMPERIALISM 0x00516260
short TMapMgr::GetCoastTileNumber(char bitmaskIndex, char direction) {
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
short TMapMgr::GetCoastTileOffset(char bitmaskIndex, char direction,
                                                        char useAltOffset) {
  short variant = GetCoastTileNumber(bitmaskIndex, direction);
  if (variant == 0) {
    return variant;
  }
  if (useAltOffset == 0) {
    return (GetCoastTileNumber(bitmaskIndex, direction) + 0x15) << 6;
  }
  return (GetCoastTileNumber(bitmaskIndex, direction) + 0x20) << 6;
}

// FUNCTION: IMPERIALISM 0x00517480
short TMapMgr::GetDeltaTileOffset(char bitmaskIndex, char direction,
                                                              short terrainPict) {
  if (GetCoastTileNumber(bitmaskIndex, direction) == 0) {
    return 0;
  }
  short offset = GetCoastTileNumber(bitmaskIndex, direction);
  offset = (offset + 0x29) << 6;
  if (GetCoastTileNumber(bitmaskIndex, direction) == 1) {
    if (terrainPict == 0x33 || terrainPict == 0x36 || terrainPict == 0x3a || terrainPict == 0x39) {
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
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
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
short TMapMgr::GetTownOffset(StrategicTileIndex tileIndex,
                                                          int unused) {
  (void)unused;
  unsigned short flags = terrainStateTable[tileIndex].activeFlags1c;
  TTown* town = FindTownMarkerForTileByOwnerNation(tileIndex);
  bool linked = (town != nullptr) ? town->transportLinked : 1;
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
short TMapMgr::GetFortFlagOffset(short nation) {
  if (nation < 7) {
    return nation * 9;
  }
  return 0x3f;
}

// FUNCTION: IMPERIALISM 0x00517710
short TMapMgr::GetUnitOffset(TCivUnit* unit) {
  if (unit->militaryRegistrationFlag != 0) {
    return GetUnitOffset(unit->orderType, true, 0);
  }
  char idle = unit->IsInIdleSelectionState();
  return GetUnitOffset(unit->orderType, false, idle);
}

// FUNCTION: IMPERIALISM 0x00517780
short TMapMgr::GetUnitOffset(short orderType, bool military, char idle) {
  short offset;
  if (!military) {
    offset = g_anMapImprovementSpriteClassByOrderType[orderType] << 6;
    if (idle == 0) {
      return offset + 0x480;
    }
  } else {
    offset = 0x6c0;
  }
  return offset;
}

// FUNCTION: IMPERIALISM 0x005177d0
int TMapMgr::GetTinyIngotOffset(char ingotKind, int unused) {
  (void)unused;
  return ingotKind * 16;
}

// FUNCTION: IMPERIALISM 0x005177f0
short TMapMgr::GetMapImprovementTileSpriteOffset(StrategicTileIndex tileIndex) {
  TTerrainStateRecord* tile = &terrainStateTable[tileIndex];
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
  signed char* markerSlot = &terrainStateTable[0].markerSlotIndex;
  for (int tileCount = 0x1950; tileCount != 0; --tileCount) {
    *markerSlot = -1;
    markerSlot += sizeof(TTerrainStateRecord);
  }
}

// FUNCTION: IMPERIALISM 0x005178f0
short TMapMgr::ComputeRepresentativeTileIndexForNationWithWrapBias(short nationSlot,
                                                                   bool wrapBias) {
  TTerrainStateRecord* tileTable = terrainStateTable;
  Province* cityTable = cityScoreTable;
  unsigned int colSum = 0;
  int rowSum = 0;
  unsigned int tileCount = 0;
  int westCount = 0;
  unsigned int eastCount = 0;

  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    signed char ownerNationTag = tileTable[tileIndex].ownerNationTag04;
    if (ownerNationTag != nationSlot) {
      continue;
    }
    bool includeTile = true;
    if (nationSlot < 0x17 && g_apTerrainTypeDescriptorTable[nationSlot] != 0 &&
        g_apTerrainTypeDescriptorTable[nationSlot]->homeTileIndex != -1) {
      short nationHomeTile =
          static_cast<short>(g_apTerrainTypeDescriptorTable[nationSlot]->homeTileIndex);
      ProvinceIndexStorage tileCityLink = tileTable[tileIndex].cityRecordIndex;
      signed char tileCityByte = cityTable[tileCityLink].regionClassA3;
      ProvinceIndexStorage nationTileCityLink = tileTable[nationHomeTile].cityRecordIndex;
      signed char nationCityByte = cityTable[nationTileCityLink].regionClassA3;
      if (tileCityByte != nationCityByte) {
        includeTile = false;
      }
    }
    if (!includeTile) {
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
    if (!wrapBias) {
      tileCount = 0;
      rowSum = 0;
      colSum = 0;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (tileTable[tileIndex].ownerNationTag04 != nationSlot) {
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
    } else if (wrapBias) {
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
        if (tileTable[tileIndex].ownerNationTag04 == nationSlot) {
          lastMatch = tileIndex;
        }
      }
      fallbackTile = static_cast<short>(lastMatch);
    }
  }
  return fallbackTile;
}

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
    bool found = false;
    int neighborCount = record->adjacentRegionCount08;
    if (neighborCount > 0) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds[neighborIndex];
        if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationB) {
          found = true;
          break;
        }
      }
    }
    if (found) {
      return 1;
    }
    ++ordinal;
  } while (ordinal <= regionList->GetSize());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00517d40
bool TMapMgr::HasAdjacentProvinceOwnedByNation(int provinceIndex, int ownerNationCode) {
  Province* table = cityScoreTable;
  Province* province = &table[provinceIndex];
  int adjacentCount = province->adjacentRegionCount08;
  if (adjacentCount < 1) {
    return false;
  }

  int index = 0;
  ProvinceIndexStorage* neighbourId = province->adjacentRegionIds;
  do {
    if (table[*neighbourId].ownerNationCode00 == ownerNationCode) {
      return true;
    }
    index = index + 1;
    neighbourId = neighbourId + 1;
  } while (index < adjacentCount);

  return false;
}

// FUNCTION: IMPERIALISM 0x00517dd0
bool TMapMgr::HasDirectOrFallbackLinkedNodeType(ProvinceIndex cityRecordIndex, int nationCode,
                                                bool allowFallback) {
  Province* record = &cityScoreTable[cityRecordIndex];
  int neighborCount = record->adjacentRegionCount08;

  if (!allowFallback || nationCode > 6) {
    for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
      short neighborRegionId = record->adjacentRegionIds[neighborIndex];
      if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationCode) {
        return true;
      }
    }
    return false;
  }

  for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
    short neighborRegionId = record->adjacentRegionIds[neighborIndex];
    if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationCode) {
      return true;
    }
  }

  for (int minorSlot = 7; minorSlot < 0x17; ++minorSlot) {
    if (g_apTerrainTypeDescriptorTable[minorSlot] != nullptr &&
        g_apSecondaryNationStateSlots[minorSlot]->IsColonyOf(nationCode)) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds[neighborIndex];
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
    short adjacentRegion = cityScoreTable[cityRecordIndex].adjacentRegionIds[outer];
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
                                                             bool allowFallback) {
  int resultCount =
      CollectSecondDegreeLinksMatchingNodeType(cityRecordIndex, nationTag, nodeBuffer);
  if (resultCount <= 0 && allowFallback && nationTag >= 7) {
    int minorIndex;
    for (minorIndex = 0; minorIndex < 16; ++minorIndex) {
      if (g_apTerrainTypeDescriptorTable[7 + minorIndex] != 0 &&
          g_apSecondaryNationStateSlots[7 + minorIndex]->IsColonyOf(nationTag) != 0) {
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

namespace {

const unsigned char kHeatmapPackedDevelopmentOverflow[44] = {
    0, 0, 0,  1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    1, 0, 10, 0, 4, 0, 7, 0, 6, 0, 8, 0, 0, 0, 9, 0, 5, 0, 1, 0, 2, 0};

unsigned char GetHeatmapRequirementLevel(int resourceType, signed char packedDevelopment) {
  const int flatIndex = resourceType * 4 + packedDevelopment;
  if (flatIndex < static_cast<int>(sizeof(g_abUniversityRequirementLevelById))) {
    return g_abUniversityRequirementLevelById[flatIndex / 4][flatIndex % 4];
  }
  return kHeatmapPackedDevelopmentOverflow[flatIndex - static_cast<int>(sizeof(
                                                           g_abUniversityRequirementLevelById))];
}

} // namespace

// FUNCTION: IMPERIALISM 0x00518130
void TMapMgr::RecomputeTileStrategicScoreHeatmap() {
  int r;
  int i;
  int edge;
  int resourceWeights[kResourceKindCount] = {0};
  for (int resType = 0; resType < kResourceManufacturedEnd; ++resType) {
    resourceWeights[resType] = g_pTradeMgr->GetBasePrice(static_cast<short>(resType));
  }
  resourceWeights[kResourceGems] = 500;
  resourceWeights[kResourceGold] = 200;

  int regionScores[0x180];

  // Pass 1: base each region's score on the resource yields of its linked tiles.
  Province* region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    int score = 200;
    int linkedCount = region->linkedRegionCount;
    if (linkedCount > 0) {
      StrategicTileIndex* linkedTile = region->linkedTileIndices42;
      do {
        TTerrainStateRecord* tile = &terrainStateTable[*linkedTile];
        for (edge = 0; edge < 2; ++edge) {
          int resType = tile->resourceTypeByEdge[edge];
          if ((resType != kResourceOil ||
               g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId] != 0) &&
              resType != -1) {
            score += GetHeatmapRequirementLevel(resType, tile->developmentClassNibbles) *
                     resourceWeights[resType];
          }
        }
        ++linkedTile;
      } while (--linkedCount != 0);
    }
    regionScores[r] = score;
    ++region;
  }

  // Pass 2: development-stage bonus.
  region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    regionScores[r] += (region->developmentStage + 3) * 1000;
    ++region;
  }

  // Pass 3: terrain-type descriptor bonuses (first 7 weighted higher than the next 16).
  for (i = 0; i < 7; ++i) {
    if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
      short idx = static_cast<short>(g_apTerrainTypeDescriptorTable[i]->GetCapitolProvince());
      regionScores[idx] += 10000;
    }
  }
  for (i = 7; i < 23; ++i) {
    if (g_apTerrainTypeDescriptorTable[i] != nullptr) {
      short idx = static_cast<short>(g_apTerrainTypeDescriptorTable[i]->GetCapitolProvince());
      regionScores[idx] += 8000;
    }
  }

  region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    region->cityScoreValue = regionScores[r];
    for (i = region->adjacentRegionCount08 - 1; i >= 0; --i) {
      short adjIdx = region->adjacentRegionIds[i];
      region->cityScoreValue = static_cast<int>(
          regionScores[adjIdx] * g_TileHeatmapNeighborDiffusionFactor + region->cityScoreValue);
    }
    ++region;
  }

  // Pass 5: cityScoreTotal = mean region score.
  cityScoreTotal = 0;
  region = cityScoreTable;
  for (r = 0; r < 0x180; ++r) {
    cityScoreTotal += region->cityScoreValue;
    ++region;
  }
  cityScoreTotal = cityScoreTotal / 0x180;
}

// FUNCTION: IMPERIALISM 0x00518470
void TMapMgr::ApplyJoinEmpireMode0GlobalDiplomacyReset(int nationSlot) {
  signed char* tagCursor = &terrainStateTable->ownerNationTag04;
  int tileIndex = 0;
  do {
    if (*tagCursor >= 7 && *tagCursor <= 0x16) {
      signed char* ownerByte =
          &terrainStateTable[static_cast<short>(tileIndex)].secondaryOwnerNationTag;
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
  (void)provinceId;
  return 0x21;
}

// FUNCTION: IMPERIALISM 0x00518540
char TMapMgr::LoadScenarioMapStateFromTableResource(int scenarioIndex) {
  CString scenarioPath;
  g_pAssetMgr->GetScenarioFileName(scenarioIndex, 1, &scenarioPath);
  if (TryGetFileMetadataForPath(&scenarioPath) == 0) {
    return 0;
  }

  CFile* stream = g_pAssetMgr->LoadTableResourceStreamByName(scenarioPath);

  // Raw terrain table: 0x1950 records x 0x24 bytes.
  int byteCount = 0x38f40;
  int nameCapacity = 0x20;
  g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, terrainStateTable, &byteCount);

  byteCount = 0xa4;
  int recordCount = 0x180;
  Province* record = cityScoreTable;
  do {
    int nameLengthBytes;
    char nameText[0x20];
    g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, record, &byteCount);
    nameLengthBytes = 2;
    g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, nameText, &nameLengthBytes);
    g_pAssetMgr->ReadResourceStreamIntoBufferAndAdvance(stream, nameText, &nameCapacity);
    CString cityName(nameText);
    record->cityNameA4 = cityName;
    ++record;
    --recordCount;
  } while (recordCount != 0);
  g_pAssetMgr->ReleaseResourceStreamIfNotNull(stream);

  // Endian fixup of the per-tile short fields + clear the transient order chain.
  {
    TTerrainStateRecord* tile = terrainStateTable;
    int tileCount = 0x1950;
    do {
      SwapShortBytes(&tile->cityRecordIndex);
      SwapShortBytes(&tile->tileActionOrdinal);
      SwapShortBytes(&tile->activeFlags1c);
      tile->firstCivilianOrder20 = 0;
      ++tile;
      --tileCount;
    } while (tileCount != 0);
  }

  ByteSwapCityScoreTableShortFields(cityScoreTable);

  int row;
  for (row = 0; row < 0x3c; ++row) {
    short rowTile = static_cast<short>(row * 0x6c);
    if (terrainStateTable[rowTile].GetTerrainKind() == kStrategicTerrainWater) {
      terrainStateTable[rowTile].waterAdjacencyMask = 0;
      terrainStateTable[rowTile].adjacencyMaskB0b = 0;
      terrainStateTable[rowTile].spriteVariantIndex = 0;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005187f0
void ByteSwapScenarioTileRecordWords(ScenarioTileDiskRecord* tileRecords) {
  ScenarioTileDiskRecord* record = tileRecords;
  unsigned char* swapCursor = &record->tileActionOrdinal[1];
  int remaining = 0x1950;
  do {
    unsigned char low = swapCursor[-7];
    swapCursor[-7] = swapCursor[-6];
    swapCursor[-6] = low;
    low = swapCursor[-1];
    swapCursor[-1] = swapCursor[0];
    swapCursor[0] = low;
    low = swapCursor[1];
    swapCursor[1] = swapCursor[2];
    swapCursor[2] = low;
    record->transientPointerBits = 0;
    swapCursor += sizeof(ScenarioTileDiskRecord);
    ++record;
    --remaining;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x00518840
void ByteSwapCityScoreTableShortFields(Province* table) {
  Province* record = table;
  int recordCount = 0x180;
  do {
    SwapShortBytes(&record->cityTileIndex04);
    SwapShortBytes(&record->lastTurnTick);
    int k = 0xc;
    short* idSlot = record->adjacentRegionIds;
    do {
      SwapShortBytes(&idSlot[0]);
      SwapShortBytes(&idSlot[0xc]);
      ++idSlot;
      --k;
    } while (k != 0);
    SwapShortBytes(&record->secondaryNeighborTileIndex);
    SwapShortBytes(&record->primaryNeighborTileIndex);
    k = 0x20;
    StrategicTileIndex* linkedSlot = record->linkedTileIndices42;
    do {
      SwapShortBytes(linkedSlot);
      ++linkedSlot;
      --k;
    } while (k != 0);
    k = 0xa;
    short* devSlot = record->resourceDevelopmentCounts;
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

// ORACLE: Mac TMapMgr::HasPortInProvince(int). The Windows listing returns true as soon as
// one linked tile has activeFlags1c bit 2 (the port flag) set.
// FUNCTION: IMPERIALISM 0x00518a20
char TMapMgr::HasPortInProvince(int provinceIndex) {
  const Province& record = cityScoreTable[provinceIndex];
  for (int i = 0; i < record.linkedRegionCount; ++i) {
    unsigned char flags = terrainStateTable[record.linkedTileIndices42[i]].activeFlags1c;
    if ((flags >> 2) & 1) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00518aa0
char TMapMgr::HasActiveLinkedTileWithReachableSea(int regionIndex) {
  Province& record = cityScoreTable[regionIndex];
  for (int i = 0; i < record.linkedRegionCount; ++i) {
    StrategicTileIndex tileIndex = record.linkedTileIndices42[i];
    unsigned char flags = terrainStateTable[tileIndex].activeFlags1c;
    flags >>= 2;
    flags &= 1;
    if (flags != 0 && HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(tileIndex) != 0) {
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
      if (resourceType < kResourceManufacturedEnd) {
        total = total + g_pTradeMgr->GetPrice(resourceType) * 0x14;
      } else if (resourceType == kResourceGems) {
        total = total + 10000;
      } else if (resourceType == kResourceGold) {
        total = total + 4000;
      }
    }
    edge = edge + 1;
  } while (edge < 2);
  return total;
}

// FUNCTION: IMPERIALISM 0x00518bd0
void TMapMgr::ActivateMarchingArrow(int tileIndex, int contextArg, bool flag) {
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
    if (flag) {
      directionCode += 6;
    }
    g_pGlobalMapState->terrainStateTable[finalTileIndex].perTileVisitedFlag = directionCode;
    if (g_pViewMgr->mapUberPictureF0 != nullptr) {
      g_pViewMgr->mapUberPictureF0->InvalidateTile(finalTileIndex);
    }
  }
}

namespace {
const unsigned char kGateFlagScoreBucket[15] = {0, 0, 0, 0, 1, 1, 2, 2, 2, 3, 4, 2, 2, 7, 2};
} // namespace

// FUNCTION: IMPERIALISM 0x00518d90
void TMapMgr::MarkDirectionalMapOverlayFlagsForNationOrders() {
  DimmingOff();

  short activeNationId = g_pSimMgr->GetPlayerCountry();
  CIterator cursor(g_apNationStates[activeNationId]->militaryUnitList44);
  TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
  while (cursor.More()) {
    if (unit->orderTargetIndex != -1) {
      bool atWar = g_pDiplomacyTurnStateManager->IsNationPairAtWar(
          activeNationId, cityScoreTable[unit->orderTargetIndex].ownerNationCode00);
      ActivateMarchingArrow(unit->tileIndex06, unit->orderTargetIndex, atWar);
    }
    unit = static_cast<TMilitaryUnit*>(cursor.Advance());
  }
}

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
  int i;
  do {
    Province& record = cityScoreTable[recordIndex];
    record.adjacentRegionCount08 = 0;
    record.byte3B = 0;
    record.byte3C = 0;
    record.secondaryNeighborTileIndex = -1;
    record.primaryNeighborTileIndex = -1;
    for (i = 0; i < 12; ++i) {
      record.adjacentRegionIds[i] = -1;
      record.adjacentRegionAnchorTiles[i] = -1;
    }
    record.linkedRegionCount = 0;
    for (i = 0; i < 32; ++i) {
      record.linkedTileIndices42[i] = -1;
    }
    TMilitaryUnit* unit = record.stationedUnitChain;
    if (unit != 0) {
      short armyCountByType[30];
      for (i = 0; i < 30; ++i) {
        armyCountByType[i] = 0;
      }
      do {
        armyCountByType[unit->orderType]++;
        unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation);
      } while (unit != 0);
      for (i = 0; i < 30; ++i) {
        if (armyCountByType[i] > 0) {
          fprintf(logFile, g_szFmtArmy_006972bc, recordIndex, i, armyCountByType[i]);
        }
      }
    }
    record.stationedUnitChain = 0;
    record.regionClassA3 = -1;
    recordIndex++;
  } while (recordIndex < 0x180);

  int tileIndex = 0;
  do {
    TTerrainStateRecord& tile = terrainStateTable[tileIndex];
    TCivUnit* civilianOrder = tile.firstCivilianOrder20;
    if (civilianOrder != 0) {
      fprintf(logFile, g_szFmtCivi_006972ac, civilianOrder->orderType, tileIndex);
      tile.firstCivilianOrder20 = 0;
    }
    unsigned short flags = tile.activeFlags1c;
    if ((flags & 4) != 0) {
      if ((flags & 1) == 0) {
        fprintf(logFile, g_szFmtPort_006972a0, tileIndex);
      }
      tile.activeFlags1c &= 0xfffb;
    }
    flags = tile.activeFlags1c;
    if ((flags & 0x10) != 0) {
      if ((flags & 1) == 0) {
        fprintf(logFile, g_szFmtRail_00697294, tileIndex);
      }
      tile.activeFlags1c &= 0xffef;
    }
    tile.regionSubtypeTag = -1;
    tile.tileActionState16 = -1;
    tileIndex++;
  } while (tileIndex < 0x1950);

  int slot;
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    TGreatPower* nation = g_apNationStates[nationIndex];
    for (slot = 0; slot < 6; ++slot) {
      TCity* city = (nation != nullptr) ? nation->city : nullptr;
      int value = city->GetBuildingType(static_cast<short>(slot));
      if (static_cast<short>(value) > 0) {
        fprintf(logFile, g_szFmtCapa_00697280, nationIndex, slot, static_cast<short>(value));
      }
    }
    TCity* laborCity1 = (nation != nullptr) ? nation->city : nullptr;
    TCity* laborCity2 = (nation != nullptr) ? nation->city : nullptr;
    TCity* laborCity3 = (nation != nullptr) ? nation->city : nullptr;
    fprintf(logFile, g_szFmtLabo_00697268, nationIndex,
            laborCity1->productionSummary->baselineSlots->lowSkillCount04,
            laborCity2->productionSummary->baselineSlots->mediumSkillCount06,
            laborCity3->productionSummary->baselineSlots->highSkillCount08);
    for (slot = 0; slot < 0x17; ++slot) {
      short embargo =
          g_pDiplomacyTurnStateManager->GetEmbassyStatus(nationIndex, slot);
      if (embargo > 0) {
        embargo =
            g_pDiplomacyTurnStateManager->GetEmbassyStatus(nationIndex, slot);
        fprintf(logFile, g_szFmtEmba_00697254, nationIndex, slot, embargo);
      }
    }
  }

  fprintf(logFile, g_szFmtYear_00697248, g_pSimMgr->economicTurn / 4);
  fclose(logFile);
  g_pAmbitApplication->PostWmCloseToMainThreadWindow();
}

// FUNCTION: IMPERIALISM 0x00519610
void TMapMgr::ChooseNationSetupProfilesForOpenSlots(short* outProfileBySlot) {
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

  Province* record = cityScoreTable;
  for (recordsLeft = 0x180; recordsLeft != 0; --recordsLeft) {
    if (record->ownerNationCode00 != -1) {
      nationRegionClass[record->ownerNationCode00] = record->regionClassA3;
    }
    ++record;
  }

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

// FUNCTION: IMPERIALISM 0x0051da60
void __stdcall UnusedMapManagerLeaf(StrategicTileIndex nTileIndex) {
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
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[nTileIndex];
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
      if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
        return -1;
      }
      col = 0x6b;
    }
  } else if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionEast) ||
             (direction < EncodeStrategicHexDirection(kStrategicHexDirectionSouthWest) &&
              (row & 1U) != 0U)) {
    col = col + 1;
    if (col > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
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

// Advances a tile without applying the north/south map-edge rejection used by TMapMgr.
// FUNCTION: IMPERIALISM 0x0055e470
StrategicTileIndex StepStrategicTileIndexAcrossWrappedRow(StrategicTileIndex tileIndex,
                                                          StrategicHexDirectionStorage direction) {
  int column = tileIndex % 0x6c;
  unsigned int row = static_cast<unsigned int>(tileIndex / 0x6c);
  if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionWest) ||
      (direction > EncodeStrategicHexDirection(kStrategicHexDirectionSouthEast) &&
       (row & 1U) == 0U)) {
    if (g_pGlobalMapState->hexNeighborWrapHorizontally == 0 && --column < 0) {
      column = 0x6b;
    }
  } else if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionEast) ||
             (direction < EncodeStrategicHexDirection(kStrategicHexDirectionSouthWest) &&
              (row & 1U) != 0U)) {
    if (g_pGlobalMapState->hexNeighborWrapHorizontally == 0 && ++column > 0x6b) {
      column = 0;
    }
  }
  if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionNorthWest) ||
      direction == EncodeStrategicHexDirection(kStrategicHexDirectionNorthEast)) {
    --row;
  } else if (direction == EncodeStrategicHexDirection(kStrategicHexDirectionSouthWest) ||
             direction == EncodeStrategicHexDirection(kStrategicHexDirectionSouthEast)) {
    ++row;
  }
  return static_cast<StrategicTileIndex>(column + row * 0x6c);
}

// FUNCTION: IMPERIALISM 0x0055e550
bool TMapMgr::StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction) {
  if (direction == kStrategicHexDirectionWest ||
      (direction > kStrategicHexDirectionSouthEast && ((*row) & 1) == 0)) {
    int nextCol = *col - 1;
    *col = nextCol;
    if (nextCol < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
        return false;
      }
      *col = 0x6b;
    }
  } else if (direction == kStrategicHexDirectionEast ||
             (direction < kStrategicHexDirectionSouthWest && ((*row) & 1) != 0)) {
    int nextCol = *col + 1;
    *col = nextCol;
    if (nextCol > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally != 0) {
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

// Checks the signed range of the 108 by 60 strategic-map tile table.
// FUNCTION: IMPERIALISM 0x0055e630
bool IsValidStrategicTileIndex(short tileIndex) {
  return tileIndex >= 0 && tileIndex < 0x1950;
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
  TTerrainStateRecord* terrainTable = g_pGlobalMapState->terrainStateTable;
  for (int flowVariant = 0; flowVariant < 2; ++flowVariant) {
    short flowType = static_cast<short>(terrainTable[tileIndex].riverSpriteCode);
    if (flowType == kRiverSpriteCodeNone) {
      return -1;
    }
    if (flowType > kRiverSpriteCodeFlowLast &&
        flowType < kRiverSpriteCodeLandSingleDirectionFirst) {
      flowType = static_cast<short>(flowType - kRiverSpriteCodeFlowVariantBias);
    }
    if (flowType >= kRiverSpriteCodeFlowFirst && flowType <= kRiverSpriteCodeFlowLast) {
      flowType = g_anTerrainFlowTypeByRiverSpriteCode[flowType - kRiverSpriteCodeFlowFirst];
    } else if (flowType >= kRiverSpriteCodeLandSingleDirectionFirst &&
               flowType <= kRiverSpriteCodeWaterSingleDirectionLast) {
      return -1;
    }

    short stepDirection = g_anTerrainFlowDirections[flowType][flowVariant];
    short walkTile = tileIndex;
    for (int stepCount = 0; stepCount < 100; ++stepCount) {
      walkTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
      TTerrainStateRecord& walkRecord = terrainTable[walkTile];
      if (walkRecord.GetTerrainKind() == kStrategicTerrainWater) {
        return walkTile;
      }

      short nextFlowType = static_cast<short>(walkRecord.riverSpriteCode);
      if (nextFlowType == kRiverSpriteCodeNone) {
        break;
      }
      if (nextFlowType > kRiverSpriteCodeFlowLast &&
          nextFlowType < kRiverSpriteCodeLandSingleDirectionFirst) {
        nextFlowType = static_cast<short>(nextFlowType - kRiverSpriteCodeFlowVariantBias);
      }
      if (nextFlowType >= kRiverSpriteCodeFlowFirst && nextFlowType <= kRiverSpriteCodeFlowLast) {
        nextFlowType =
            g_anTerrainFlowTypeByRiverSpriteCode[nextFlowType - kRiverSpriteCodeFlowFirst];
      } else if (nextFlowType >= kRiverSpriteCodeLandSingleDirectionFirst &&
                 nextFlowType <= kRiverSpriteCodeWaterSingleDirectionLast) {
        break;
      }

      short preferredDirection = static_cast<short>((static_cast<int>(stepDirection) + 3) % 6);
      const short* directionPair = g_anTerrainFlowDirections[nextFlowType];
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

// FUNCTION: IMPERIALISM 0x00563b70
char __stdcall EvaluateTerrainFlowCrossNationBoundaryToSea(StrategicTileIndex tileIndex) {
  TTerrainStateRecord* terrainTable = g_pGlobalMapState->terrainStateTable;
  signed char startOwnerNation = terrainTable[tileIndex].ownerNationTag04;

  for (int attempt = 0; attempt < 2; ++attempt) {
    short flowType = static_cast<short>(terrainTable[tileIndex].riverSpriteCode);
    bool crossedBoundary = false;
    if (flowType == kRiverSpriteCodeNone) {
      return static_cast<char>(0xff);
    }
    if (flowType > kRiverSpriteCodeFlowLast &&
        flowType < kRiverSpriteCodeLandSingleDirectionFirst) {
      flowType = static_cast<short>(flowType - kRiverSpriteCodeFlowVariantBias);
    }
    if (flowType >= kRiverSpriteCodeFlowFirst && flowType <= kRiverSpriteCodeFlowLast) {
      flowType = g_anTerrainFlowTypeByRiverSpriteCode[flowType - kRiverSpriteCodeFlowFirst];
    } else if (flowType >= kRiverSpriteCodeLandSingleDirectionFirst &&
               flowType <= kRiverSpriteCodeWaterSingleDirectionLast) {
      return static_cast<char>(0xff);
    }

    short stepDirection = g_anTerrainFlowDirections[flowType][attempt];
    short walkTile = tileIndex;
    for (int stepCount = 0; stepCount < 100; ++stepCount) {
      walkTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
      if (walkTile == -1) {
        return crossedBoundary;
      }
      TTerrainStateRecord& walkRecord = terrainTable[walkTile];
      if (walkRecord.GetTerrainKind() == kStrategicTerrainWater) {
        return crossedBoundary;
      }

      short nextFlowType = static_cast<short>(walkRecord.riverSpriteCode);
      if (nextFlowType == kRiverSpriteCodeNone) {
        break;
      }
      if (nextFlowType > kRiverSpriteCodeFlowLast &&
          nextFlowType < kRiverSpriteCodeLandSingleDirectionFirst) {
        nextFlowType = static_cast<short>(nextFlowType - kRiverSpriteCodeFlowVariantBias);
      }
      if (nextFlowType >= kRiverSpriteCodeFlowFirst && nextFlowType <= kRiverSpriteCodeFlowLast) {
        nextFlowType =
            g_anTerrainFlowTypeByRiverSpriteCode[nextFlowType - kRiverSpriteCodeFlowFirst];
      } else if (nextFlowType >= kRiverSpriteCodeLandSingleDirectionFirst &&
                 nextFlowType <= kRiverSpriteCodeWaterSingleDirectionLast) {
        break;
      }

      if (startOwnerNation != walkRecord.ownerNationTag04) {
        if (attempt > 0) {
          return 1;
        }
        crossedBoundary = true;
      }

      short preferredDirection = static_cast<short>((static_cast<int>(stepDirection) + 3) % 6);
      const short* directionPair = g_anTerrainFlowDirections[nextFlowType];
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
