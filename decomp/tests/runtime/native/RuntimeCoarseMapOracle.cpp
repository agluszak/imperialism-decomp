#include "RuntimeCoarseMapOracle.h"

#include "game/map/map_records.h"
#include "game/map_generation/TMapMaker.h"
#include "parson.h"

namespace {

JSON_Value* g_currentCoarseGeneration = 0;
JSON_Value* g_lastCoarseGeneration = 0;
JSON_Object* g_currentCoarseAttempt = 0;
int g_attemptDrawCount = 0;

JSON_Value* g_terrainGeneration = 0;
JSON_Value* g_currentTerrainAttemptValue = 0;
JSON_Object* g_currentTerrainAttempt = 0;
int g_topologyByte = 0;
int g_terrainRotationColumn = -1;
int g_terrainSeedCandidates[23];

void ReplaceValue(JSON_Value*& destination, JSON_Value* value) {
  if (destination != 0) {
    json_value_free(destination);
  }
  destination = value;
}

JSON_Value* MakeNumberArray(const int* values, int count) {
  JSON_Value* value = json_value_init_array();
  JSON_Array* array = json_value_get_array(value);
  for (int index = 0; index < count; ++index) {
    json_array_append_number(array, static_cast<double>(values[index]));
  }
  return value;
}

JSON_Value* MakeGrid(const TMapMaker* mapMaker) {
  JSON_Value* value = json_value_init_object();
  JSON_Object* grid = json_value_get_object(value);
  JSON_Value* cellsValue = json_value_init_array();
  JSON_Array* cells = json_value_get_array(cellsValue);
  for (int row = 0; row < 15; ++row) {
    JSON_Value* rowValue = json_value_init_array();
    JSON_Array* rowArray = json_value_get_array(rowValue);
    for (int column = 0; column < 27; ++column) {
      json_array_append_number(rowArray,
                               static_cast<double>(mapMaker->regionClassGrid10[row][column]));
    }
    json_array_append_value(cells, rowValue);
  }
  json_object_set_value(grid, "cells", cellsValue);
  return value;
}

JSON_Value* MakeCityRegionIds(const TMapMaker* mapMaker) {
  JSON_Value* value = json_value_init_array();
  JSON_Array* array = json_value_get_array(value);
  for (int index = 0; index < 23; ++index) {
    json_array_append_number(array, static_cast<double>(mapMaker->cityRegionIds200[index]));
  }
  return value;
}

JSON_Value* MakeGroupMembers(const TMapMaker* mapMaker) {
  JSON_Value* value = json_value_init_array();
  JSON_Array* groups = json_value_get_array(value);
  for (int group = 0; group < 7; ++group) {
    JSON_Value* membersValue = json_value_init_array();
    JSON_Array* members = json_value_get_array(membersValue);
    for (int member = 0; member < 3; ++member) {
      json_array_append_number(members,
                               static_cast<double>(mapMaker->groupMemberLists1a8[group][member]));
    }
    json_array_append_value(groups, membersValue);
  }
  return value;
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

JSON_Value* MakeExpandedTiles(const TMapMaker* mapMaker) {
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  JSON_Value* value = json_value_init_array();
  JSON_Array* array = json_value_get_array(value);
  for (int index = 0; index < 108 * 60; ++index) {
    JSON_Value* tileValue = json_value_init_object();
    JSON_Object* tile = json_value_get_object(tileValue);
    json_object_set_number(tile, "terrain_kind",
                           static_cast<double>(tiles[index].GetTerrainKind()));
    json_object_set_number(tile, "owner_nation",
                           static_cast<double>(tiles[index].ownerNationTag04));
    json_object_set_number(tile, "province_index",
                           static_cast<double>(tiles[index].cityRecordIndex));
    json_array_append_value(array, tileValue);
  }
  return value;
}

JSON_Value* MakeExpandedProvinces(const TMapMaker* mapMaker, int count) {
  JSON_Value* value = json_value_init_array();
  JSON_Array* array = json_value_get_array(value);
  for (int index = 0; index < count; ++index) {
    const Province& province = mapMaker->cityScoreTable0c[index];
    JSON_Value* provinceValue = json_value_init_object();
    JSON_Object* provinceObject = json_value_get_object(provinceValue);
    json_object_set_number(provinceObject, "owner_nation",
                           static_cast<double>(province.ownerNationCode00));
    json_object_set_number(provinceObject, "region_class",
                           static_cast<double>(province.regionClassA3));
    json_array_append_value(array, provinceValue);
  }
  return value;
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

JSON_Value* MakeTerrainStage(const TMapMaker* mapMaker, unsigned int mapLcg,
                             bool ignoreWaterOwnership) {
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
  JSON_Value* value = json_value_init_object();
  JSON_Object* stage = json_value_get_object(value);
  json_object_set_number(stage, "map_lcg", static_cast<double>(mapLcg));
  json_object_set_number(stage, "tile_hash",
                         static_cast<double>(HashTerrainTiles(mapMaker, ignoreWaterOwnership)));
  JSON_Value* countsValue = json_value_init_array();
  JSON_Array* terrainCounts = json_value_get_array(countsValue);
  for (int terrainIndex = 0; terrainIndex < 8; ++terrainIndex) {
    json_array_append_number(terrainCounts, static_cast<double>(counts[terrainIndex]));
  }
  json_object_set_value(stage, "terrain_counts", countsValue);
  json_object_set_number(stage, "river_tile_count", static_cast<double>(riverTileCount));
  return value;
}

} // namespace

void RuntimeCoarseMapOracleReset(unsigned int initialMapLcg) {
  (void)initialMapLcg;
  ReplaceValue(g_currentCoarseGeneration, 0);
  ReplaceValue(g_lastCoarseGeneration, 0);
  g_currentCoarseAttempt = 0;
  g_attemptDrawCount = 0;
}

void RuntimeCoarseMapOracleBeginGenerationAttempt(unsigned int initialMapLcg) {
  ReplaceValue(g_currentCoarseGeneration, json_value_init_object());
  JSON_Object* generation = json_value_get_object(g_currentCoarseGeneration);
  json_object_set_number(generation, "initial_map_lcg", static_cast<double>(initialMapLcg));
  json_object_set_value(generation, "attempts", json_value_init_array());
  g_currentCoarseAttempt = 0;
  g_attemptDrawCount = 0;
}

void RuntimeCoarseMapOracleBeginAttempt() {
  g_attemptDrawCount = 0;
}

void RuntimeCoarseMapOracleRecordDraw() {
  ++g_attemptDrawCount;
}

void RuntimeCoarseMapOracleCaptureSeededAttempt(const TMapMaker* mapMaker, unsigned int mapLcg) {
  if (g_currentCoarseGeneration == 0) {
    return;
  }
  JSON_Object* generation = json_value_get_object(g_currentCoarseGeneration);
  JSON_Array* attempts = json_object_get_array(generation, "attempts");
  JSON_Value* attemptValue = json_value_init_object();
  JSON_Object* attempt = json_value_get_object(attemptValue);
  json_object_set_number(attempt, "draw_count", static_cast<double>(g_attemptDrawCount));
  json_object_set_number(attempt, "map_lcg_after_seeding", static_cast<double>(mapLcg));
  json_object_set_value(attempt, "pre_validation_grid", MakeGrid(mapMaker));
  json_object_set_number(attempt, "city_region_next_id",
                         static_cast<double>(mapMaker->cityRegionNextId1fc));
  json_object_set_value(attempt, "city_region_ids", MakeCityRegionIds(mapMaker));
  json_object_set_value(attempt, "group_members", MakeGroupMembers(mapMaker));
  json_array_append_value(attempts, attemptValue);
  g_currentCoarseAttempt = attempt;
}

void RuntimeCoarseMapOracleFinishAttempt(const TMapMaker* mapMaker, int errorCheckFailed,
                                         int hasContinuousOceanColumn, int frontierMaskComplete,
                                         int accepted, unsigned int mapLcg) {
  if (g_currentCoarseAttempt == 0) {
    return;
  }
  json_object_set_value(g_currentCoarseAttempt, "post_validation_grid", MakeGrid(mapMaker));
  json_object_set_boolean(g_currentCoarseAttempt, "error_check_failed", errorCheckFailed != 0);
  if (hasContinuousOceanColumn < 0) {
    json_object_set_null(g_currentCoarseAttempt, "has_continuous_ocean_column");
  } else {
    json_object_set_boolean(g_currentCoarseAttempt, "has_continuous_ocean_column",
                            hasContinuousOceanColumn != 0);
  }
  if (frontierMaskComplete < 0) {
    json_object_set_null(g_currentCoarseAttempt, "frontier_mask_complete");
  } else {
    json_object_set_boolean(g_currentCoarseAttempt, "frontier_mask_complete",
                            frontierMaskComplete != 0);
  }
  json_object_set_boolean(g_currentCoarseAttempt, "accepted", accepted != 0);
  json_object_set_number(g_currentCoarseAttempt, "map_lcg_after_validation",
                         static_cast<double>(mapLcg));
  g_currentCoarseAttempt = 0;
}

void RuntimeCoarseMapOracleCaptureExpansion(const TMapMaker* mapMaker, unsigned int mapLcg) {
  if (g_currentCoarseGeneration == 0) {
    return;
  }
  JSON_Object* generation = json_value_get_object(g_currentCoarseGeneration);
  json_object_set_number(generation, "accepted_map_lcg", static_cast<double>(mapLcg));
  json_object_set_value(generation, "accepted_grid", MakeGrid(mapMaker));
  json_object_set_number(generation, "city_region_next_id",
                         static_cast<double>(mapMaker->cityRegionNextId1fc));
  json_object_set_value(generation, "city_region_ids", MakeCityRegionIds(mapMaker));
  json_object_set_value(generation, "group_members", MakeGroupMembers(mapMaker));
  int provinceCount = ExpandedProvinceCount(mapMaker);
  json_object_set_value(generation, "expanded_tiles", MakeExpandedTiles(mapMaker));
  json_object_set_value(generation, "expanded_provinces",
                        MakeExpandedProvinces(mapMaker, provinceCount));
  ReplaceValue(g_lastCoarseGeneration, json_value_deep_copy(g_currentCoarseGeneration));
}

const JSON_Value* RuntimeCoarseMapOracleValue() {
  return g_lastCoarseGeneration;
}

void RuntimeTerrainMapOracleReset(unsigned int initialMapLcg, int topologyByte, int desertQuota,
                                  int mountainQuota, int hillsQuota, int forestQuota,
                                  int swampQuota, int riverCount, int regionRows,
                                  int regionColumns) {
  if (g_currentTerrainAttemptValue != 0) {
    json_value_free(g_currentTerrainAttemptValue);
    g_currentTerrainAttemptValue = 0;
  }
  ReplaceValue(g_terrainGeneration, json_value_init_object());
  g_currentTerrainAttempt = 0;
  g_topologyByte = topologyByte;
  JSON_Object* generation = json_value_get_object(g_terrainGeneration);
  JSON_Value* tuningValue = json_value_init_object();
  JSON_Object* tuning = json_value_get_object(tuningValue);
  json_object_set_number(tuning, "desert_quota", static_cast<double>(desertQuota));
  json_object_set_number(tuning, "mountain_quota", static_cast<double>(mountainQuota));
  json_object_set_number(tuning, "hills_quota", static_cast<double>(hillsQuota));
  json_object_set_number(tuning, "forest_quota", static_cast<double>(forestQuota));
  json_object_set_number(tuning, "swamp_quota", static_cast<double>(swampQuota));
  json_object_set_number(tuning, "river_count", static_cast<double>(riverCount));
  json_object_set_number(tuning, "region_seed_rows", static_cast<double>(regionRows));
  json_object_set_number(tuning, "region_seed_columns", static_cast<double>(regionColumns));
  json_object_set_value(generation, "tuning", tuningValue);
  json_object_set_number(generation, "initial_map_lcg", static_cast<double>(initialMapLcg));
  json_object_set_value(generation, "attempts", json_value_init_array());
  json_object_set_number(generation, "final_map_lcg", static_cast<double>(initialMapLcg));
}

void RuntimeTerrainMapOracleBeginAttempt(const TMapMaker* mapMaker, unsigned int mapLcg) {
  if (g_terrainGeneration == 0 || g_lastCoarseGeneration == 0) {
    return;
  }
  g_terrainRotationColumn = -1;
  JSON_Value* attemptValue = json_value_init_object();
  JSON_Object* attempt = json_value_get_object(attemptValue);
  json_object_set_value(attempt, "coarse_generation", json_value_deep_copy(g_lastCoarseGeneration));
  json_object_set_value(attempt, "after_expansion", MakeTerrainStage(mapMaker, mapLcg, false));
  g_currentTerrainAttemptValue = attemptValue;
  g_currentTerrainAttempt = attempt;
}

void RuntimeTerrainMapOracleCaptureStage(const char* stageName, const TMapMaker* mapMaker,
                                         unsigned int mapLcg) {
  if (g_currentTerrainAttempt != 0) {
    json_object_set_value(g_currentTerrainAttempt, stageName,
                          MakeTerrainStage(mapMaker, mapLcg, false));
  }
}

void RuntimeTerrainMapOracleRecordRotationColumn(int column) {
  g_terrainRotationColumn = column;
}

void RuntimeTerrainMapOracleCaptureKeywordStage(const TMapMaker* mapMaker, unsigned int mapLcg) {
  if (g_currentTerrainAttempt != 0) {
    json_object_set_value(g_currentTerrainAttempt, "after_keyword",
                          MakeTerrainStage(mapMaker, mapLcg, true));
  }
}

void RuntimeTerrainMapOracleResetSeedCandidates() {
  for (int index = 0; index < 23; ++index) {
    g_terrainSeedCandidates[index] = 0;
  }
}

void RuntimeTerrainMapOracleRecordSeedCandidate(int terrainClass, int tileIndex) {
  g_terrainSeedCandidates[terrainClass] = tileIndex;
}

void RuntimeTerrainMapOracleFinishAttempt(int accepted, unsigned int mapLcg) {
  if (g_currentTerrainAttempt == 0 || g_currentTerrainAttemptValue == 0 ||
      g_terrainRotationColumn < 0) {
    return;
  }
  json_object_set_number(g_currentTerrainAttempt, "map_lcg_after_validation",
                         static_cast<double>(mapLcg));
  json_object_set_number(g_currentTerrainAttempt, "rotation_column",
                         static_cast<double>(g_terrainRotationColumn));
  json_object_set_value(g_currentTerrainAttempt, "seed_candidate_tiles",
                        MakeNumberArray(g_terrainSeedCandidates, 23));
  json_object_set_boolean(g_currentTerrainAttempt, "accepted", accepted != 0);
  JSON_Object* generation = json_value_get_object(g_terrainGeneration);
  JSON_Array* attempts = json_object_get_array(generation, "attempts");
  json_array_append_value(attempts, g_currentTerrainAttemptValue);
  json_object_set_number(generation, "final_map_lcg", static_cast<double>(mapLcg));
  g_currentTerrainAttemptValue = 0;
  g_currentTerrainAttempt = 0;
}

const JSON_Value* RuntimeTerrainMapOracleValue() {
  return g_terrainGeneration;
}

int RuntimeTerrainMapOracleTopologyByte() {
  return g_topologyByte;
}
