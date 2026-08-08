#include "RuntimeCoarseMapOracle.h"

#include "game/map/map_records.h"
#include "game/map_generation/TMapMaker.h"
#include "game/mfc.h"

namespace {

CString g_attemptsJson;
CString g_oracleJson;
unsigned int g_initialMapLcg;
int g_attemptCount;
int g_attemptDrawCount;
CString g_terrainAttemptsJson;
CString g_terrainOracleJson;
int g_terrainAttemptCount;
int g_topologyByte;
int g_desertQuota;
int g_mountainQuota;
int g_hillsQuota;
int g_forestQuota;
int g_swampQuota;
int g_riverCount;
int g_regionRows;
int g_regionColumns;
int g_terrainRotationColumn;
int g_terrainSeedCandidates[23];

void AppendGrid(CString& json, const TMapMaker* mapMaker) {
  json += "[";
  for (int row = 0; row < 15; ++row) {
    for (int column = 0; column < 27; ++column) {
      CString item;
      item.Format("%s%d", row == 0 && column == 0 ? "" : ",",
                  static_cast<int>(mapMaker->regionClassGrid10[row][column]));
      json += item;
    }
  }
  json += "]";
}

void AppendCityRegionIds(CString& json, const TMapMaker* mapMaker) {
  json += "[";
  for (int index = 0; index < 23; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", mapMaker->cityRegionIds200[index]);
    json += item;
  }
  json += "]";
}

void AppendGroupMembers(CString& json, const TMapMaker* mapMaker) {
  json += "[";
  for (int group = 0; group < 7; ++group) {
    for (int member = 0; member < 3; ++member) {
      CString item;
      item.Format("%s%d", group == 0 && member == 0 ? "" : ",",
                  mapMaker->groupMemberLists1a8[group][member]);
      json += item;
    }
  }
  json += "]";
}

void AppendExpandedTiles(CString& json, const TMapMaker* mapMaker) {
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  json += "[";
  for (int index = 0; index < 108 * 60; ++index) {
    CString item;
    item.Format("%s[%d,%d,%d]", index == 0 ? "" : ",",
                static_cast<int>(tiles[index].GetTerrainKind()),
                static_cast<int>(tiles[index].ownerNationTag04),
                static_cast<int>(tiles[index].cityRecordIndex));
    json += item;
  }
  json += "]";
}

void AppendExpandedProvinces(CString& json, const TMapMaker* mapMaker, int count) {
  json += "[";
  for (int index = 0; index < count; ++index) {
    const Province& province = mapMaker->cityScoreTable0c[index];
    CString item;
    item.Format("%s[%d,%d]", index == 0 ? "" : ",", static_cast<int>(province.ownerNationCode00),
                static_cast<int>(province.regionClassA3));
    json += item;
  }
  json += "]";
}

int ExpandedProvinceCount(const TMapMaker* mapMaker) {
  int count = 0;
  for (int row = 0; row < 15; ++row) {
    for (int column = 0; column < 27; ++column) {
      signed char value = mapMaker->regionClassGrid10[row][column];
      if (value != -1 && value != 100) {
        ++count;
      }
    }
  }
  return count;
}

unsigned int HashTerrainTiles(const TMapMaker* mapMaker, bool ignoreWaterOwnership) {
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  unsigned int hash = 0x811c9dc5;
  for (int index = 0; index < 108 * 60; ++index) {
    bool water = tiles[index].GetTerrainKind() == kStrategicTerrainWater;
    signed char owner = ignoreWaterOwnership && water ? -1 : tiles[index].ownerNationTag04;
    short province = ignoreWaterOwnership && water ? -1 : tiles[index].cityRecordIndex;
    const unsigned char bytes[] = {static_cast<unsigned char>(tiles[index].GetTerrainKind()),
                                   static_cast<unsigned char>(tiles[index].riverSpriteCode),
                                   static_cast<unsigned char>(owner),
                                   static_cast<unsigned char>(tiles[index].gateFlag),
                                   static_cast<unsigned char>(province),
                                   static_cast<unsigned char>(province >> 8)};
    for (int byte = 0; byte < 6; ++byte) {
      hash = (hash ^ bytes[byte]) * 0x1000193;
    }
  }
  return hash;
}

void AppendTerrainCounts(CString& json, const TMapMaker* mapMaker) {
  int counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  int riverTileCount = 0;
  for (int index = 0; index < 108 * 60; ++index) {
    int terrain = static_cast<int>(tiles[index].GetTerrainKind());
    if (terrain >= 0 && terrain < 8) {
      ++counts[terrain];
    }
    if (tiles[index].riverSpriteCode != 0) {
      ++riverTileCount;
    }
  }
  CString value;
  value.Format("[%d,%d,%d,%d,%d,%d,%d,%d],\"river_tile_count\":%d", counts[0], counts[1], counts[2],
               counts[3], counts[4], counts[5], counts[6], counts[7], riverTileCount);
  json += value;
}

void AppendTerrainStage(CString& json, const char* stageName, const TMapMaker* mapMaker,
                        unsigned int mapLcg) {
  CString prefix;
  prefix.Format(",\"%s\":{\"map_lcg\":%u,\"tile_hash\":%u,\"terrain_counts\":", stageName, mapLcg,
                HashTerrainTiles(mapMaker, false));
  json += prefix;
  AppendTerrainCounts(json, mapMaker);
  json += "}";
}

void AppendTerrainTiles(CString& json, const TMapMaker* mapMaker) {
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  json += "[";
  for (int index = 0; index < 108 * 60; ++index) {
    CString item;
    item.Format("%s[%d,%u,%d,%d,%d]", index == 0 ? "" : ",",
                static_cast<int>(tiles[index].GetTerrainKind()),
                static_cast<unsigned int>(tiles[index].riverSpriteCode),
                static_cast<int>(tiles[index].ownerNationTag04),
                static_cast<int>(tiles[index].gateFlag),
                static_cast<int>(tiles[index].cityRecordIndex));
    json += item;
  }
  json += "]";
}

void AppendTerrainSeedCandidates(CString& json) {
  json += "[";
  for (int index = 0; index < 23; ++index) {
    CString item;
    item.Format("%s%d", index == 0 ? "" : ",", g_terrainSeedCandidates[index]);
    json += item;
  }
  json += "]";
}

} // namespace

void RuntimeCoarseMapOracleReset(unsigned int initialMapLcg) {
  g_attemptsJson = "[";
  g_oracleJson.Empty();
  g_initialMapLcg = initialMapLcg;
  g_attemptCount = 0;
  g_attemptDrawCount = 0;
}

void RuntimeCoarseMapOracleBeginAttempt() {
  g_attemptDrawCount = 0;
}

void RuntimeCoarseMapOracleRecordDraw() {
  ++g_attemptDrawCount;
}

void RuntimeCoarseMapOracleCaptureSeededAttempt(const TMapMaker* mapMaker, unsigned int mapLcg) {
  CString prefix;
  prefix.Format("%s{\"index\":%d,\"draw_count\":%d,\"map_lcg_after_seeding\":%u,"
                "\"pre_validation_grid\":",
                g_attemptCount == 0 ? "" : ",", g_attemptCount, g_attemptDrawCount, mapLcg);
  g_attemptsJson += prefix;
  AppendGrid(g_attemptsJson, mapMaker);
  g_attemptsJson += ",\"city_region_next_id\":";
  CString nextId;
  nextId.Format("%d", mapMaker->cityRegionNextId1fc);
  g_attemptsJson += nextId;
  g_attemptsJson += ",\"city_region_ids\":";
  AppendCityRegionIds(g_attemptsJson, mapMaker);
  g_attemptsJson += ",\"group_members\":";
  AppendGroupMembers(g_attemptsJson, mapMaker);
}

void RuntimeCoarseMapOracleFinishAttempt(const TMapMaker* mapMaker, int errorCheckFailed,
                                         int hasContinuousOceanColumn, int frontierMaskComplete,
                                         int accepted, unsigned int mapLcg) {
  g_attemptsJson += ",\"post_validation_grid\":";
  AppendGrid(g_attemptsJson, mapMaker);
  CString tail;
  tail.Format(",\"error_check_failed\":%d,\"has_continuous_ocean_column\":%d,"
              "\"frontier_mask_complete\":%d,\"accepted\":%d,"
              "\"map_lcg_after_validation\":%u}",
              errorCheckFailed, hasContinuousOceanColumn, frontierMaskComplete, accepted, mapLcg);
  g_attemptsJson += tail;
  ++g_attemptCount;
}

void RuntimeCoarseMapOracleCaptureExpansion(const TMapMaker* mapMaker, unsigned int mapLcg) {
  g_attemptsJson += "]";
  CString header;
  header.Format("{\"initial_map_lcg\":%u,\"attempt_count\":%d,\"attempts\":%s,"
                "\"accepted_map_lcg\":%u,\"accepted_grid\":",
                g_initialMapLcg, g_attemptCount, static_cast<LPCSTR>(g_attemptsJson), mapLcg);
  g_oracleJson = header;
  AppendGrid(g_oracleJson, mapMaker);
  g_oracleJson += ",\"city_region_next_id\":";
  CString nextId;
  nextId.Format("%d", mapMaker->cityRegionNextId1fc);
  g_oracleJson += nextId;
  g_oracleJson += ",\"city_region_ids\":";
  AppendCityRegionIds(g_oracleJson, mapMaker);
  g_oracleJson += ",\"group_members\":";
  AppendGroupMembers(g_oracleJson, mapMaker);
  int provinceCount = ExpandedProvinceCount(mapMaker);
  CString count;
  count.Format(",\"expanded_province_count\":%d,\"expanded_tile_fields\":"
               "[\"terrain_kind\",\"owner_nation\",\"province_index\"],"
               "\"expanded_tiles\":",
               provinceCount);
  g_oracleJson += count;
  AppendExpandedTiles(g_oracleJson, mapMaker);
  g_oracleJson += ",\"expanded_provinces\":";
  AppendExpandedProvinces(g_oracleJson, mapMaker, provinceCount);
  g_oracleJson += "}";
}

const CString& RuntimeCoarseMapOracleJson() {
  return g_oracleJson;
}

void RuntimeTerrainMapOracleReset(int topologyByte, int desertQuota, int mountainQuota,
                                  int hillsQuota, int forestQuota, int swampQuota, int riverCount,
                                  int regionRows, int regionColumns) {
  g_terrainAttemptsJson = "[";
  g_terrainOracleJson.Empty();
  g_terrainAttemptCount = 0;
  g_topologyByte = topologyByte;
  g_desertQuota = desertQuota;
  g_mountainQuota = mountainQuota;
  g_hillsQuota = hillsQuota;
  g_forestQuota = forestQuota;
  g_swampQuota = swampQuota;
  g_riverCount = riverCount;
  g_regionRows = regionRows;
  g_regionColumns = regionColumns;
}

void RuntimeTerrainMapOracleBeginAttempt(const TMapMaker* mapMaker, unsigned int mapLcg) {
  g_terrainRotationColumn = -1;
  CString prefix;
  prefix.Format("%s{\"index\":%d,\"map_lcg_after_expansion\":%u,"
                "\"after_expansion\":{\"map_lcg\":%u,\"tile_hash\":%u,"
                "\"terrain_counts\":",
                g_terrainAttemptCount == 0 ? "" : ",", g_terrainAttemptCount, mapLcg, mapLcg,
                HashTerrainTiles(mapMaker, false));
  g_terrainAttemptsJson += prefix;
  AppendTerrainCounts(g_terrainAttemptsJson, mapMaker);
  g_terrainAttemptsJson += "}";
}

void RuntimeTerrainMapOracleCaptureStage(const char* stageName, const TMapMaker* mapMaker,
                                         unsigned int mapLcg) {
  AppendTerrainStage(g_terrainAttemptsJson, stageName, mapMaker, mapLcg);
}

void RuntimeTerrainMapOracleRecordRotationColumn(int column) {
  g_terrainRotationColumn = column;
}

void RuntimeTerrainMapOracleCaptureKeywordStage(const TMapMaker* mapMaker, unsigned int mapLcg) {
  CString prefix;
  prefix.Format(",\"after_keyword\":{\"map_lcg\":%u,\"tile_hash\":%u,"
                "\"terrain_counts\":",
                mapLcg, HashTerrainTiles(mapMaker, true));
  g_terrainAttemptsJson += prefix;
  AppendTerrainCounts(g_terrainAttemptsJson, mapMaker);
  g_terrainAttemptsJson += "}";
}

void RuntimeTerrainMapOracleResetSeedCandidates() {
  for (int index = 0; index < 23; ++index) {
    g_terrainSeedCandidates[index] = 0;
  }
}

void RuntimeTerrainMapOracleRecordSeedCandidate(int terrainClass, int tileIndex) {
  g_terrainSeedCandidates[terrainClass] = tileIndex;
}

void RuntimeTerrainMapOracleFinishAttempt(const TMapMaker* mapMaker, int accepted,
                                          unsigned int mapLcg) {
  CString tail;
  tail.Format(",\"accepted\":%d,\"map_lcg_after_validation\":%u,\"rotation_column\":%d,"
              "\"seed_candidate_tiles\":",
              accepted, mapLcg, g_terrainRotationColumn);
  g_terrainAttemptsJson += tail;
  AppendTerrainSeedCandidates(g_terrainAttemptsJson);
  g_terrainAttemptsJson += ",\"tile_fields\":[\"terrain_kind\",\"river_sprite_code\","
                           "\"owner_nation\",\"gate_flag\",\"province_index\"],\"tiles\":";
  AppendTerrainTiles(g_terrainAttemptsJson, mapMaker);
  g_terrainAttemptsJson += "}";
  ++g_terrainAttemptCount;
}

const CString& RuntimeTerrainMapOracleJson() {
  CString header;
  header.Format("{\"topology_byte\":%d,\"tuning\":{\"desert_quota\":%d,"
                "\"mountain_quota\":%d,\"hills_quota\":%d,\"forest_quota\":%d,"
                "\"swamp_quota\":%d,\"river_count\":%d,\"region_seed_rows\":%d,"
                "\"region_seed_columns\":%d},\"attempt_count\":%d,\"attempts\":%s]}",
                g_topologyByte, g_desertQuota, g_mountainQuota, g_hillsQuota, g_forestQuota,
                g_swampQuota, g_riverCount, g_regionRows, g_regionColumns, g_terrainAttemptCount,
                static_cast<LPCSTR>(g_terrainAttemptsJson));
  g_terrainOracleJson = header;
  return g_terrainOracleJson;
}
