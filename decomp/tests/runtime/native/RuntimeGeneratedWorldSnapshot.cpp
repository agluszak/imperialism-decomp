#include "RuntimeGeneratedWorldSnapshot.h"

#include "RuntimeCoarseMapOracle.h"
#include "RuntimeJson.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/globals/game_session_globals.h"
#include "game/globals/map_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/map/map_records.h"
#include "game/map/sea_geometry.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TPortZone.h"

// VC5 libcmt rand.obj stores the thread-local LCG state at +0x14 in the block returned
// by _getptd. This is the same vendored-rand.obj-backed observation used by
// RuntimeGameSnapshot; no CRT implementation detail enters production source.
extern "C" void* __cdecl _getptd(void);

namespace {

unsigned int RuntimeCrtRandState() {
  struct CrtThreadDataPrefix {
    unsigned char prefix00[0x14];
    unsigned int randState14;
  };
  CrtThreadDataPrefix* threadData = static_cast<CrtThreadDataPrefix*>(_getptd());
  return threadData != 0 ? threadData->randState14 : 0;
}

void AppendShortArray(CString& json, const short* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", static_cast<int>(values[index]));
    json += item;
  }
  json += "]";
}

void AppendProvinceIndexArray(CString& json, const ProvinceIndexStorage* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", static_cast<int>(values[index]));
    json += item;
  }
  json += "]";
}

void AppendTileIndexArray(CString& json, const StrategicTileIndex* values, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", static_cast<int>(values[index]));
    json += item;
  }
  json += "]";
}

CString CaptureMapHeader() {
  CString json;
  json = "{\"width\":108,\"height\":60,\"scenario_tag\":";
  RuntimeJson::AppendString(json, static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText));
  CString tail;
  tail.Format(",\"retail_topology_byte\":%d,\"wraps_horizontally\":%s,"
              "\"strategic_map_palette_preview_ready\":%u,\"map_manager_ready\":%d,"
              "\"map_data_ready\":%u,\"tile_search_flag\":%u,"
              "\"city_score_total\":%d,\"pending_river_mouth_tile\":%d}",
              static_cast<int>(g_pGlobalMapState->hexNeighborWrapHorizontally),
              g_pGlobalMapState->hexNeighborWrapHorizontally == 0 ? "true" : "false",
              static_cast<unsigned int>(g_pGlobalMapState->strategicMapPalettePreviewReady),
              static_cast<int>(g_pGlobalMapState->field6),
              static_cast<unsigned int>(g_pGlobalMapState->field8),
              static_cast<unsigned int>(g_pGlobalMapState->field9),
              g_pGlobalMapState->cityScoreTotal,
              static_cast<int>(g_pGlobalMapState->pendingRiverMouthTile));
  json += tail;
  return json;
}

CString CaptureRng(const RuntimeRun& run) {
  CString json;
  json.Format("{\"runtime_seed\":%u,\"crt_rand_state\":%u,"
              "\"map_generation_lcg\":%u,\"zone_status_lcg\":%u}",
              run.Seed(), RuntimeCrtRandState(), g_mapGenLcgState_006a38e8,
              g_zoneStatusCodePrngSeed_006a5aec);
  return json;
}

CString CaptureTiles() {
  CString json("[");
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    CString row;
    row.Format(
        "%s[%d,%d,%d,%d,%d,%d,%d,%u,%u,%u,%u,%u,%d,%u,%u,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%u]",
        tileIndex == 0 ? "" : ",", static_cast<int>(tile.GetTerrainKind()),
        static_cast<int>(tile.spriteVariantIndex01), static_cast<int>(tile.riverSpriteCode),
        static_cast<int>(tile.formerOwnerNationTag03), static_cast<int>(tile.ownerNationTag04),
        static_cast<int>(tile.regionSubtypeTag05), static_cast<int>(tile.adjacencyBits06),
        static_cast<unsigned int>(tile.ownerBorderMask07),
        static_cast<unsigned int>(tile.cityBorderMask08),
        static_cast<unsigned int>(tile.waterAdjacencyMask09),
        static_cast<unsigned int>(tile.adjacencyMaskA0a),
        static_cast<unsigned int>(tile.adjacencyMaskB0b),
        static_cast<int>(tile.developmentClassNibbles0c),
        static_cast<unsigned int>(tile.pendingDevelopmentFlag0d),
        static_cast<unsigned int>(tile.recruitSearchVisited0e),
        static_cast<int>(tile.perTileVisitedFlag0f), static_cast<int>(tile.markerSlotIndex10),
        static_cast<int>(tile.resourceTypeByEdge[0]), static_cast<int>(tile.resourceTypeByEdge[1]),
        static_cast<int>(tile.gateFlag), static_cast<int>(tile.cityRecordIndex),
        static_cast<int>(tile.tileActionState16), static_cast<int>(tile.railFlags17),
        static_cast<int>(tile.secondaryOwnerNationTag18),
        static_cast<int>(tile.tileActionOrdinal1a), static_cast<unsigned int>(tile.activeFlags1c));
    json += row;
  }
  json += "]";
  return json;
}

CString CaptureProvinces() {
  CString json("[");
  for (int provinceIndex = 0; provinceIndex < 0x180; ++provinceIndex) {
    const Province& province = g_pGlobalMapState->cityScoreTable[provinceIndex];
    CString row;
    row.Format("%s{\"index\":%d,\"owner_nation\":%d,\"former_owner_nation\":%d,"
               "\"development_stage\":%d,\"fort_level\":%d,\"city_tile\":%d,"
               "\"last_turn_tick\":%d,\"adjacent_region_count\":%d,"
               "\"adjacent_region_ids\":",
               provinceIndex == 0 ? "" : ",", provinceIndex,
               static_cast<int>(province.ownerNationCode00),
               static_cast<int>(province.formerOwnerNationCode01),
               static_cast<int>(province.developmentStage), static_cast<int>(province.fortLevel03),
               static_cast<int>(province.cityTileIndex04), static_cast<int>(province.lastTurnTick),
               static_cast<int>(province.adjacentRegionCount08));
    json += row;
    AppendProvinceIndexArray(json, province.adjacentRegionIds0A, 0x0c);
    json += ",\"adjacent_region_anchor_tiles\":";
    AppendTileIndexArray(json, province.adjacentRegionAnchorTiles22, 0x0c);
    row.Format(",\"linked_region_count\":%d,\"secondary_neighbor_tile\":%d,"
               "\"primary_neighbor_tile\":%d,\"linked_tile_indices\":",
               static_cast<int>(province.linkedRegionCount),
               static_cast<int>(province.secondaryNeighborTileIndex3e),
               static_cast<int>(province.primaryNeighborTileIndex40));
    json += row;
    AppendTileIndexArray(json, province.linkedTileIndices42, 0x20);
    json += ",\"resource_development_counts\":";
    AppendShortArray(json, province.resourceDevelopmentCounts82, 10);
    row.Format(",\"city_score\":%d,\"navy_order_reachable\":%u,"
               "\"explored_by_nation_mask\":%u,\"resource_presence_mask\":%d,"
               "\"region_class\":%d,\"city_name\":",
               province.cityScoreValue, static_cast<unsigned int>(province.navyOrderReachableA0),
               static_cast<unsigned int>(province.exploredByNationMaskA1),
               static_cast<int>(province.resourcePresenceMaskA2),
               static_cast<int>(province.regionClassA3));
    json += row;
    RuntimeJson::AppendString(json, static_cast<LPCSTR>(province.cityNameA4));
    json += "}";
  }
  json += "]";
  return json;
}

void AppendPrimaryNeighbors(CString& json, const TZone& zone) {
  json += "[";
  for (int index = 0; index < zone.primaryNeighbors.GetSize(); ++index) {
    TZone* neighbor = zone.primaryNeighbors.GetAt(index);
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",",
                neighbor != 0 ? static_cast<int>(neighbor->contextOrdinal14) : -1);
    json += item;
  }
  json += "]";
}

void AppendSecondaryNeighbors(CString& json, const TZone& zone) {
  json += "[";
  for (int index = 0; index < zone.secondaryNeighbors.GetSize(); ++index) {
    Province* neighbor = zone.secondaryNeighbors.GetAt(index);
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",",
                neighbor != 0 ? static_cast<int>(neighbor->GetIndex()) : -1);
    json += item;
  }
  json += "]";
}

CString CaptureSeaRegions() {
  CString json("[");
  int index = 0;
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    bool isPort = zone->QueryPortZoneCapability();
    CString row;
    row.Format("%s{\"index\":%d,\"kind\":\"%s\",\"context_ordinal\":%d,"
               "\"status_code\":%d,\"display_name\":",
               index == 0 ? "" : ",", index, isPort ? "port" : "zone",
               static_cast<int>(zone->contextOrdinal14), static_cast<int>(zone->statusCode04));
    json += row;
    RuntimeJson::AppendString(json, static_cast<LPCSTR>(zone->displayName));
    row.Format(",\"tile_or_terrain_id\":%d,\"nation_key_mask\":%u,"
               "\"seed_nation_id\":%d,\"active_tile\":%d,\"distance_level\":%d,"
               "\"port_tile\":%d,\"primary_neighbors\":",
               zone->tileOrTerrainId0c, static_cast<unsigned int>(zone->nationKeyMask10),
               static_cast<int>(zone->seedNationId12), static_cast<int>(zone->activeTileIndex20),
               static_cast<int>(zone->distanceLevel44),
               isPort ? static_cast<int>(static_cast<TPortZone*>(zone)->portTileIndex48) : -1);
    json += row;
    AppendPrimaryNeighbors(json, *zone);
    json += ",\"secondary_neighbors\":";
    AppendSecondaryNeighbors(json, *zone);
    json += "}";
    ++index;
  }
  json += "]";
  return json;
}

CString CaptureRoutes() {
  CString json("[");
  if (g_pActiveMapOrderContext != 0) {
    for (int index = 0; index < g_pActiveMapOrderContext->routeNodeCount; ++index) {
      const CRect& route = g_pActiveMapOrderContext->routeSegments[index];
      CString row;
      row.Format("%s[%d,%d,%d,%d]", index == 0 ? "" : ",", route.left, route.top, route.right,
                 route.bottom);
      json += row;
    }
  }
  json += "]";
  return json;
}

CString CaptureBorderLinks() {
  CString json("[");
  int outputIndex = 0;
  for (int index = 0; index < g_regionBorderLinkTable_006a3900.Count(); ++index) {
    const SeaSegment* link = g_regionBorderLinkTable_006a3900.At(index);
    if (link == 0 || (link->x0 == link->x1 && link->y0 == link->y1)) {
      continue;
    }
    CString row;
    row.Format("%s[%d,%d,%d,%d,%d,%d,%d,%d,%d,%u]", outputIndex == 0 ? "" : ",",
               static_cast<int>(link->x0), static_cast<int>(link->y0), static_cast<int>(link->x1),
               static_cast<int>(link->y1), link->coord0, link->coord1,
               static_cast<int>(link->attr10), static_cast<int>(link->attr12),
               static_cast<int>(link->angle14), static_cast<unsigned int>(link->wrap16));
    json += row;
    ++outputIndex;
  }
  json += "]";
  return json;
}

} // namespace

bool BuildRuntimeGeneratedWorldSnapshot(const RuntimeRun& run, CString& snapshotJson) {
  if (g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0 ||
      g_pGlobalMapState->cityScoreTable == 0 || g_pActiveMapOrderContext == 0) {
    return false;
  }

  CString map(CaptureMapHeader());
  CString rng(CaptureRng(run));
  CString tiles(CaptureTiles());
  CString provinces(CaptureProvinces());
  CString seaRegions(CaptureSeaRegions());
  CString routes(CaptureRoutes());
  CString borderLinks(CaptureBorderLinks());
  const CString& coarseGeneration = RuntimeCoarseMapOracleJson();
  const CString& terrainGeneration = RuntimeTerrainMapOracleJson();
  if (coarseGeneration.IsEmpty() || terrainGeneration.IsEmpty()) {
    return false;
  }
  snapshotJson.Format(
      "{\"tile_fields\":[\"terrain_kind\",\"sprite_variant\",\"river_sprite_code\","
      "\"former_owner_nation\",\"owner_nation\",\"region_subtype\",\"adjacency_bits\","
      "\"owner_border_mask\",\"city_border_mask\",\"water_adjacency_mask\","
      "\"adjacency_mask_a\",\"adjacency_mask_b\",\"development_class_nibbles\","
      "\"pending_development_flag\",\"recruit_search_visited\",\"per_tile_visited_flag\","
      "\"marker_slot_index\",\"resource_edge_0\",\"resource_edge_1\",\"gate_flag\","
      "\"province_index\",\"tile_action_state\",\"rail_flags\","
      "\"secondary_owner_nation\",\"tile_action_ordinal\",\"active_flags\"],"
      "\"border_link_fields\":[\"x0\",\"y0\",\"x1\",\"y1\",\"coord0\",\"coord1\","
      "\"region_a\",\"region_b\",\"angle\",\"wrap\"],"
      "\"map\":%s,\"rng\":%s,\"coarse_generation\":%s,\"terrain_generation\":%s,"
      "\"tiles\":%s,\"provinces\":%s,"
      "\"ocean_context_array_count\":%d,\"sea_region_count\":%d,\"sea_regions\":%s,"
      "\"route_count\":%d,\"routes\":%s,\"border_links\":%s}",
      static_cast<LPCSTR>(map), static_cast<LPCSTR>(rng), static_cast<LPCSTR>(coarseGeneration),
      static_cast<LPCSTR>(terrainGeneration), static_cast<LPCSTR>(tiles),
      static_cast<LPCSTR>(provinces), static_cast<int>(g_pActiveMapOrderContext->nationCount),
      g_nMapActionContextCount, static_cast<LPCSTR>(seaRegions),
      static_cast<int>(g_pActiveMapOrderContext->routeNodeCount), static_cast<LPCSTR>(routes),
      static_cast<LPCSTR>(borderLinks));
  return true;
}

void CaptureRuntimeGeneratedWorldSnapshot(RuntimeRun& run) {
  if (!run.CapturesSnapshot(kRuntimeSnapshotGeneratedWorld) ||
      !run.GeneratedWorldSnapshotJson().IsEmpty()) {
    return;
  }
  BuildRuntimeGeneratedWorldSnapshot(run, run.GeneratedWorldSnapshotJson());
}
