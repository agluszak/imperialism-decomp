#include "RuntimeCoarseMapOracle.h"

#include "JsonArray.h"
#include "JsonObject.h"

#include "game/map/map_records.h"
#include "game/map_generation/TMapMaker.h"

#include <string.h>

namespace {

enum {
  kCoarseWidth = 27,
  kCoarseHeight = 15,
  kClassCount = 23,
  kExpandedWidth = 108,
  kExpandedHeight = 60,
  kExpandedTileCount = kExpandedWidth * kExpandedHeight,
  kMaxProvinces = kCoarseWidth * kCoarseHeight
};

struct CoarseMapGridDto {
  signed char cells[kCoarseHeight][kCoarseWidth];
};

struct ExpandedTileDto {
  signed char terrain_kind;
  signed char owner_nation;
  short province_index;
};

struct ExpandedProvinceDto {
  signed char owner_nation;
  signed char region_class;
};

struct CoarseAttempt {
  unsigned int draw_count;
  unsigned int map_lcg_after_seeding;
  CoarseMapGridDto pre_validation_grid;
  int city_region_next_id;
  int city_region_ids[kClassCount];
  int group_members[7][3];
  CoarseMapGridDto post_validation_grid;
  bool error_check_failed;
  // -1 means JSON null; otherwise 0/1.
  int has_continuous_ocean_column;
  int frontier_mask_complete;
  bool accepted;
  unsigned int map_lcg_after_validation;
  bool seeded;
  bool finished;
};

struct CoarseMapTrace {
  unsigned int initial_map_lcg;
  CoarseAttempt* attempts;
  int attempt_count;
  int attempt_capacity;
  bool complete;
  unsigned int accepted_map_lcg;
  CoarseMapGridDto accepted_grid;
  int city_region_next_id;
  int city_region_ids[kClassCount];
  int group_members[7][3];
  ExpandedTileDto expanded_tiles[kExpandedTileCount];
  ExpandedProvinceDto expanded_provinces[kMaxProvinces];
  int expanded_province_count;
};

struct TerrainStage {
  unsigned int map_lcg;
  unsigned int tile_hash;
  unsigned int terrain_counts[8];
  unsigned int river_tile_count;
  bool present;
};

struct TerrainTuning {
  int desert_quota;
  int mountain_quota;
  int hills_quota;
  int forest_quota;
  int swamp_quota;
  int river_count;
  int region_seed_rows;
  int region_seed_columns;
};

struct TerrainAttempt {
  CoarseMapTrace coarse_generation;
  TerrainStage after_expansion;
  TerrainStage after_templates;
  TerrainStage after_features;
  TerrainStage after_rotation;
  TerrainStage after_water_regions;
  TerrainStage after_keyword;
  unsigned int map_lcg_after_validation;
  int rotation_column;
  int seed_candidate_tiles[kClassCount];
  bool accepted;
  bool active;
};

struct TerrainTrace {
  TerrainTuning tuning;
  unsigned int initial_map_lcg;
  TerrainAttempt* attempts;
  int attempt_count;
  int attempt_capacity;
  unsigned int final_map_lcg;
  bool present;
};

CoarseMapTrace g_currentCoarse;
CoarseMapTrace g_lastCoarse;
bool g_hasLastCoarse = false;
unsigned int g_attemptDrawCount = 0;
JSON_Value* g_serializedCoarse = 0;

TerrainTrace g_terrain;
TerrainAttempt g_currentTerrainAttempt;
int g_topologyByte = 0;
JSON_Value* g_serializedTerrain = 0;

void FreeAttempts(CoarseAttempt*& attempts, int& count, int& capacity) {
  delete[] attempts;
  attempts = 0;
  count = 0;
  capacity = 0;
}

void FreeTerrainAttempts(TerrainAttempt*& attempts, int& count, int& capacity) {
  if (attempts != 0) {
    for (int index = 0; index < count; ++index) {
      FreeAttempts(attempts[index].coarse_generation.attempts,
                   attempts[index].coarse_generation.attempt_count,
                   attempts[index].coarse_generation.attempt_capacity);
    }
  }
  delete[] attempts;
  attempts = 0;
  count = 0;
  capacity = 0;
}

void ClearCoarseTrace(CoarseMapTrace& trace) {
  FreeAttempts(trace.attempts, trace.attempt_count, trace.attempt_capacity);
  memset(&trace, 0, sizeof(trace));
}

void EnsureCoarseAttemptCapacity(CoarseMapTrace& trace, int needed) {
  if (needed <= trace.attempt_capacity) {
    return;
  }
  int capacity = trace.attempt_capacity == 0 ? 4 : trace.attempt_capacity * 2;
  while (capacity < needed) {
    capacity *= 2;
  }
  CoarseAttempt* next = new CoarseAttempt[capacity];
  for (int index = 0; index < trace.attempt_count; ++index) {
    next[index] = trace.attempts[index];
  }
  delete[] trace.attempts;
  trace.attempts = next;
  trace.attempt_capacity = capacity;
}

void EnsureTerrainAttemptCapacity(TerrainTrace& trace, int needed) {
  if (needed <= trace.attempt_capacity) {
    return;
  }
  int capacity = trace.attempt_capacity == 0 ? 4 : trace.attempt_capacity * 2;
  while (capacity < needed) {
    capacity *= 2;
  }
  TerrainAttempt* next = new TerrainAttempt[capacity];
  for (int index = 0; index < trace.attempt_count; ++index) {
    next[index] = trace.attempts[index];
    // Ownership of attempt arrays moved; clear source pointers so FreeTerrainAttempts
    // on the old buffer does not double-free.
    trace.attempts[index].coarse_generation.attempts = 0;
    trace.attempts[index].coarse_generation.attempt_count = 0;
    trace.attempts[index].coarse_generation.attempt_capacity = 0;
  }
  delete[] trace.attempts;
  trace.attempts = next;
  trace.attempt_capacity = capacity;
}

void CopyCoarseAttempts(CoarseMapTrace& dest, const CoarseMapTrace& src) {
  FreeAttempts(dest.attempts, dest.attempt_count, dest.attempt_capacity);
  if (src.attempt_count == 0) {
    return;
  }
  dest.attempts = new CoarseAttempt[src.attempt_count];
  dest.attempt_count = src.attempt_count;
  dest.attempt_capacity = src.attempt_count;
  for (int index = 0; index < src.attempt_count; ++index) {
    dest.attempts[index] = src.attempts[index];
  }
}

void CopyCoarseMapTrace(CoarseMapTrace& dest, const CoarseMapTrace& src) {
  dest.initial_map_lcg = src.initial_map_lcg;
  dest.complete = src.complete;
  dest.accepted_map_lcg = src.accepted_map_lcg;
  dest.accepted_grid = src.accepted_grid;
  dest.city_region_next_id = src.city_region_next_id;
  memcpy(dest.city_region_ids, src.city_region_ids, sizeof(dest.city_region_ids));
  memcpy(dest.group_members, src.group_members, sizeof(dest.group_members));
  memcpy(dest.expanded_tiles, src.expanded_tiles, sizeof(dest.expanded_tiles));
  memcpy(dest.expanded_provinces, src.expanded_provinces, sizeof(dest.expanded_provinces));
  dest.expanded_province_count = src.expanded_province_count;
  CopyCoarseAttempts(dest, src);
}

void ReplaceJson(JSON_Value*& destination, JSON_Value* value) {
  JsonFreeValue(destination);
  destination = value;
}

void FillGrid(CoarseMapGridDto& grid, const TMapMaker* mapMaker) {
  for (int row = 0; row < kCoarseHeight; ++row) {
    for (int column = 0; column < kCoarseWidth; ++column) {
      grid.cells[row][column] = mapMaker->regionClassGrid10[row][column];
    }
  }
}

void FillCityRegionIds(int* ids, const TMapMaker* mapMaker) {
  for (int index = 0; index < kClassCount; ++index) {
    ids[index] = mapMaker->cityRegionIds200[index];
  }
}

void FillGroupMembers(int members[7][3], const TMapMaker* mapMaker) {
  for (int group = 0; group < 7; ++group) {
    for (int member = 0; member < 3; ++member) {
      members[group][member] = mapMaker->groupMemberLists1a8[group][member];
    }
  }
}

int ExpandedProvinceCount(const TMapMaker* mapMaker) {
  int count = 0;
  for (int row = 0; row < kCoarseHeight; ++row) {
    for (int column = 0; column < kCoarseWidth; ++column) {
      signed char value = mapMaker->regionClassGrid10[row][column];
      if (value != -1 && value != 100) {
        ++count;
      }
    }
  }
  return count;
}

void FillExpandedTiles(ExpandedTileDto* tiles, const TMapMaker* mapMaker) {
  const TTerrainStateRecord* source =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  for (int index = 0; index < kExpandedTileCount; ++index) {
    tiles[index].terrain_kind = static_cast<signed char>(source[index].GetTerrainKind());
    tiles[index].owner_nation = source[index].ownerNationTag04;
    tiles[index].province_index = source[index].cityRecordIndex;
  }
}

void FillExpandedProvinces(ExpandedProvinceDto* provinces, int count, const TMapMaker* mapMaker) {
  for (int index = 0; index < count; ++index) {
    const Province& province = mapMaker->cityScoreTable0c[index];
    provinces[index].owner_nation = province.ownerNationCode00;
    provinces[index].region_class = province.regionClassA3;
  }
}

unsigned int HashTerrainTiles(const TMapMaker* mapMaker, bool ignoreWaterOwnership) {
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  unsigned int hash = 0x811c9dc5;
  for (int index = 0; index < kExpandedTileCount; ++index) {
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

void FillTerrainStage(TerrainStage& stage, const TMapMaker* mapMaker, unsigned int mapLcg,
                      bool ignoreWaterOwnership) {
  unsigned int counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  const TTerrainStateRecord* tiles =
      static_cast<const TTerrainStateRecord*>(static_cast<const void*>(mapMaker->mapTileGrid08));
  unsigned int riverTileCount = 0;
  for (int index = 0; index < kExpandedTileCount; ++index) {
    int terrain = static_cast<int>(tiles[index].GetTerrainKind());
    if (terrain >= 0 && terrain < 8) {
      ++counts[terrain];
    }
    if (tiles[index].riverSpriteCode != 0) {
      ++riverTileCount;
    }
  }
  stage.map_lcg = mapLcg;
  stage.tile_hash = HashTerrainTiles(mapMaker, ignoreWaterOwnership);
  for (int terrainIndex = 0; terrainIndex < 8; ++terrainIndex) {
    stage.terrain_counts[terrainIndex] = counts[terrainIndex];
  }
  stage.river_tile_count = riverTileCount;
  stage.present = true;
}

JSON_Value* SerializeGrid(const CoarseMapGridDto& grid) {
  JsonObject object;
  JsonArray cells;
  for (int row = 0; row < kCoarseHeight; ++row) {
    JsonArray rowArray;
    for (int column = 0; column < kCoarseWidth; ++column) {
      rowArray.Add(static_cast<int>(grid.cells[row][column]));
    }
    cells.Add(rowArray.Release());
  }
  object.Set("cells", cells.Release());
  return object.Release();
}

JSON_Value* SerializeCityRegionIds(const int* ids) {
  JsonArray array;
  for (int index = 0; index < kClassCount; ++index) {
    array.Add(ids[index]);
  }
  return array.Release();
}

JSON_Value* SerializeGroupMembers(const int members[7][3]) {
  JsonArray groups;
  for (int group = 0; group < 7; ++group) {
    JsonArray memberArray;
    for (int member = 0; member < 3; ++member) {
      memberArray.Add(members[group][member]);
    }
    groups.Add(memberArray.Release());
  }
  return groups.Release();
}

void SetOptionalBool(JsonObject& object, const char* name, int value) {
  if (value < 0) {
    object.SetNull(name);
  } else {
    object.Set(name, value != 0 ? true : false);
  }
}

JSON_Value* SerializeCoarseAttempt(const CoarseAttempt& attempt) {
  JsonObject object;
  object.Set("draw_count", attempt.draw_count);
  object.Set("map_lcg_after_seeding", attempt.map_lcg_after_seeding);
  object.Set("pre_validation_grid", SerializeGrid(attempt.pre_validation_grid));
  object.Set("city_region_next_id", attempt.city_region_next_id);
  object.Set("city_region_ids", SerializeCityRegionIds(attempt.city_region_ids));
  object.Set("group_members", SerializeGroupMembers(attempt.group_members));
  object.Set("post_validation_grid", SerializeGrid(attempt.post_validation_grid));
  object.Set("error_check_failed", attempt.error_check_failed ? true : false);
  SetOptionalBool(object, "has_continuous_ocean_column", attempt.has_continuous_ocean_column);
  SetOptionalBool(object, "frontier_mask_complete", attempt.frontier_mask_complete);
  object.Set("accepted", attempt.accepted ? true : false);
  object.Set("map_lcg_after_validation", attempt.map_lcg_after_validation);
  return object.Release();
}

JSON_Value* SerializeExpandedTiles(const ExpandedTileDto* tiles) {
  JsonArray array;
  for (int index = 0; index < kExpandedTileCount; ++index) {
    JsonObject tile;
    tile.Set("terrain_kind", static_cast<int>(tiles[index].terrain_kind));
    tile.Set("owner_nation", static_cast<int>(tiles[index].owner_nation));
    tile.Set("province_index", static_cast<int>(tiles[index].province_index));
    array.Add(tile.Release());
  }
  return array.Release();
}

JSON_Value* SerializeExpandedProvinces(const ExpandedProvinceDto* provinces, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    JsonObject province;
    province.Set("owner_nation", static_cast<int>(provinces[index].owner_nation));
    province.Set("region_class", static_cast<int>(provinces[index].region_class));
    array.Add(province.Release());
  }
  return array.Release();
}

JSON_Value* SerializeCoarseMapTrace(const CoarseMapTrace& trace) {
  JsonObject object;
  object.Set("initial_map_lcg", trace.initial_map_lcg);
  JsonArray attempts;
  for (int index = 0; index < trace.attempt_count; ++index) {
    attempts.Add(SerializeCoarseAttempt(trace.attempts[index]));
  }
  object.Set("attempts", attempts.Release());
  object.Set("accepted_map_lcg", trace.accepted_map_lcg);
  object.Set("accepted_grid", SerializeGrid(trace.accepted_grid));
  object.Set("city_region_next_id", trace.city_region_next_id);
  object.Set("city_region_ids", SerializeCityRegionIds(trace.city_region_ids));
  object.Set("group_members", SerializeGroupMembers(trace.group_members));
  object.Set("expanded_tiles", SerializeExpandedTiles(trace.expanded_tiles));
  object.Set("expanded_provinces",
             SerializeExpandedProvinces(trace.expanded_provinces, trace.expanded_province_count));
  return object.Release();
}

JSON_Value* SerializeTerrainStage(const TerrainStage& stage) {
  JsonObject object;
  object.Set("map_lcg", stage.map_lcg);
  object.Set("tile_hash", stage.tile_hash);
  JsonArray counts;
  for (int index = 0; index < 8; ++index) {
    counts.Add(stage.terrain_counts[index]);
  }
  object.Set("terrain_counts", counts.Release());
  object.Set("river_tile_count", stage.river_tile_count);
  return object.Release();
}

JSON_Value* SerializeTerrainAttempt(const TerrainAttempt& attempt) {
  JsonObject object;
  object.Set("coarse_generation", SerializeCoarseMapTrace(attempt.coarse_generation));
  object.Set("after_expansion", SerializeTerrainStage(attempt.after_expansion));
  object.Set("after_templates", SerializeTerrainStage(attempt.after_templates));
  object.Set("after_features", SerializeTerrainStage(attempt.after_features));
  object.Set("after_rotation", SerializeTerrainStage(attempt.after_rotation));
  object.Set("after_water_regions", SerializeTerrainStage(attempt.after_water_regions));
  object.Set("after_keyword", SerializeTerrainStage(attempt.after_keyword));
  object.Set("map_lcg_after_validation", attempt.map_lcg_after_validation);
  object.Set("rotation_column", attempt.rotation_column);
  JsonArray seeds;
  for (int index = 0; index < kClassCount; ++index) {
    seeds.Add(attempt.seed_candidate_tiles[index]);
  }
  object.Set("seed_candidate_tiles", seeds.Release());
  object.Set("accepted", attempt.accepted ? true : false);
  return object.Release();
}

JSON_Value* SerializeTerrainTrace(const TerrainTrace& trace) {
  JsonObject object;
  JsonObject tuning;
  tuning.Set("desert_quota", trace.tuning.desert_quota);
  tuning.Set("mountain_quota", trace.tuning.mountain_quota);
  tuning.Set("hills_quota", trace.tuning.hills_quota);
  tuning.Set("forest_quota", trace.tuning.forest_quota);
  tuning.Set("swamp_quota", trace.tuning.swamp_quota);
  tuning.Set("river_count", trace.tuning.river_count);
  tuning.Set("region_seed_rows", trace.tuning.region_seed_rows);
  tuning.Set("region_seed_columns", trace.tuning.region_seed_columns);
  object.Set("tuning", tuning.Release());
  object.Set("initial_map_lcg", trace.initial_map_lcg);
  JsonArray attempts;
  for (int index = 0; index < trace.attempt_count; ++index) {
    attempts.Add(SerializeTerrainAttempt(trace.attempts[index]));
  }
  object.Set("attempts", attempts.Release());
  object.Set("final_map_lcg", trace.final_map_lcg);
  return object.Release();
}

TerrainStage* StageByName(TerrainAttempt& attempt, const char* stageName) {
  if (strcmp(stageName, "after_templates") == 0) {
    return &attempt.after_templates;
  }
  if (strcmp(stageName, "after_features") == 0) {
    return &attempt.after_features;
  }
  if (strcmp(stageName, "after_rotation") == 0) {
    return &attempt.after_rotation;
  }
  if (strcmp(stageName, "after_water_regions") == 0) {
    return &attempt.after_water_regions;
  }
  return 0;
}

} // namespace

void RuntimeCoarseMapOracleReset(unsigned int initialMapLcg) {
  (void)initialMapLcg;
  ClearCoarseTrace(g_currentCoarse);
  ClearCoarseTrace(g_lastCoarse);
  g_hasLastCoarse = false;
  g_attemptDrawCount = 0;
  ReplaceJson(g_serializedCoarse, 0);
}

void RuntimeCoarseMapOracleBeginGenerationAttempt(unsigned int initialMapLcg) {
  ClearCoarseTrace(g_currentCoarse);
  g_currentCoarse.initial_map_lcg = initialMapLcg;
  g_attemptDrawCount = 0;
  ReplaceJson(g_serializedCoarse, 0);
}

void RuntimeCoarseMapOracleBeginAttempt() {
  g_attemptDrawCount = 0;
}

void RuntimeCoarseMapOracleRecordDraw() {
  ++g_attemptDrawCount;
}

void RuntimeCoarseMapOracleCaptureSeededAttempt(const TMapMaker* mapMaker, unsigned int mapLcg) {
  EnsureCoarseAttemptCapacity(g_currentCoarse, g_currentCoarse.attempt_count + 1);
  CoarseAttempt& attempt = g_currentCoarse.attempts[g_currentCoarse.attempt_count];
  memset(&attempt, 0, sizeof(attempt));
  attempt.draw_count = g_attemptDrawCount;
  attempt.map_lcg_after_seeding = mapLcg;
  FillGrid(attempt.pre_validation_grid, mapMaker);
  attempt.city_region_next_id = mapMaker->cityRegionNextId1fc;
  FillCityRegionIds(attempt.city_region_ids, mapMaker);
  FillGroupMembers(attempt.group_members, mapMaker);
  attempt.has_continuous_ocean_column = -1;
  attempt.frontier_mask_complete = -1;
  attempt.seeded = true;
  attempt.finished = false;
  ++g_currentCoarse.attempt_count;
}

void RuntimeCoarseMapOracleFinishAttempt(const TMapMaker* mapMaker, int errorCheckFailed,
                                         int hasContinuousOceanColumn, int frontierMaskComplete,
                                         int accepted, unsigned int mapLcg) {
  if (g_currentCoarse.attempt_count == 0) {
    return;
  }
  CoarseAttempt& attempt = g_currentCoarse.attempts[g_currentCoarse.attempt_count - 1];
  if (!attempt.seeded || attempt.finished) {
    return;
  }
  FillGrid(attempt.post_validation_grid, mapMaker);
  attempt.error_check_failed = errorCheckFailed != 0;
  attempt.has_continuous_ocean_column = hasContinuousOceanColumn;
  attempt.frontier_mask_complete = frontierMaskComplete;
  attempt.accepted = accepted != 0;
  attempt.map_lcg_after_validation = mapLcg;
  attempt.finished = true;
}

void RuntimeCoarseMapOracleCaptureExpansion(const TMapMaker* mapMaker, unsigned int mapLcg) {
  g_currentCoarse.accepted_map_lcg = mapLcg;
  FillGrid(g_currentCoarse.accepted_grid, mapMaker);
  g_currentCoarse.city_region_next_id = mapMaker->cityRegionNextId1fc;
  FillCityRegionIds(g_currentCoarse.city_region_ids, mapMaker);
  FillGroupMembers(g_currentCoarse.group_members, mapMaker);
  FillExpandedTiles(g_currentCoarse.expanded_tiles, mapMaker);
  g_currentCoarse.expanded_province_count = ExpandedProvinceCount(mapMaker);
  FillExpandedProvinces(g_currentCoarse.expanded_provinces, g_currentCoarse.expanded_province_count,
                        mapMaker);
  g_currentCoarse.complete = true;

  ClearCoarseTrace(g_lastCoarse);
  CopyCoarseMapTrace(g_lastCoarse, g_currentCoarse);
  g_hasLastCoarse = true;
  ReplaceJson(g_serializedCoarse, SerializeCoarseMapTrace(g_lastCoarse));
}

const JSON_Value* RuntimeCoarseMapOracleValue() {
  return g_serializedCoarse;
}

void RuntimeTerrainMapOracleReset(unsigned int initialMapLcg, int topologyByte, int desertQuota,
                                  int mountainQuota, int hillsQuota, int forestQuota,
                                  int swampQuota, int riverCount, int regionRows,
                                  int regionColumns) {
  if (g_currentTerrainAttempt.active) {
    FreeAttempts(g_currentTerrainAttempt.coarse_generation.attempts,
                 g_currentTerrainAttempt.coarse_generation.attempt_count,
                 g_currentTerrainAttempt.coarse_generation.attempt_capacity);
  }
  memset(&g_currentTerrainAttempt, 0, sizeof(g_currentTerrainAttempt));
  FreeTerrainAttempts(g_terrain.attempts, g_terrain.attempt_count, g_terrain.attempt_capacity);
  memset(&g_terrain, 0, sizeof(g_terrain));
  g_topologyByte = topologyByte;
  g_terrain.tuning.desert_quota = desertQuota;
  g_terrain.tuning.mountain_quota = mountainQuota;
  g_terrain.tuning.hills_quota = hillsQuota;
  g_terrain.tuning.forest_quota = forestQuota;
  g_terrain.tuning.swamp_quota = swampQuota;
  g_terrain.tuning.river_count = riverCount;
  g_terrain.tuning.region_seed_rows = regionRows;
  g_terrain.tuning.region_seed_columns = regionColumns;
  g_terrain.initial_map_lcg = initialMapLcg;
  g_terrain.final_map_lcg = initialMapLcg;
  g_terrain.present = true;
  ReplaceJson(g_serializedTerrain, 0);
}

void RuntimeTerrainMapOracleBeginAttempt(const TMapMaker* mapMaker, unsigned int mapLcg) {
  if (!g_terrain.present || !g_hasLastCoarse) {
    return;
  }
  if (g_currentTerrainAttempt.active) {
    FreeAttempts(g_currentTerrainAttempt.coarse_generation.attempts,
                 g_currentTerrainAttempt.coarse_generation.attempt_count,
                 g_currentTerrainAttempt.coarse_generation.attempt_capacity);
  }
  memset(&g_currentTerrainAttempt, 0, sizeof(g_currentTerrainAttempt));
  CopyCoarseMapTrace(g_currentTerrainAttempt.coarse_generation, g_lastCoarse);
  FillTerrainStage(g_currentTerrainAttempt.after_expansion, mapMaker, mapLcg, false);
  g_currentTerrainAttempt.rotation_column = -1;
  g_currentTerrainAttempt.active = true;
}

void RuntimeTerrainMapOracleCaptureStage(const char* stageName, const TMapMaker* mapMaker,
                                         unsigned int mapLcg) {
  if (!g_currentTerrainAttempt.active) {
    return;
  }
  TerrainStage* stage = StageByName(g_currentTerrainAttempt, stageName);
  if (stage != 0) {
    FillTerrainStage(*stage, mapMaker, mapLcg, false);
  }
}

void RuntimeTerrainMapOracleRecordRotationColumn(int column) {
  if (g_currentTerrainAttempt.active) {
    g_currentTerrainAttempt.rotation_column = column;
  }
}

void RuntimeTerrainMapOracleCaptureKeywordStage(const TMapMaker* mapMaker, unsigned int mapLcg) {
  if (g_currentTerrainAttempt.active) {
    FillTerrainStage(g_currentTerrainAttempt.after_keyword, mapMaker, mapLcg, true);
  }
}

void RuntimeTerrainMapOracleResetSeedCandidates() {
  for (int index = 0; index < kClassCount; ++index) {
    g_currentTerrainAttempt.seed_candidate_tiles[index] = 0;
  }
}

void RuntimeTerrainMapOracleRecordSeedCandidate(int terrainClass, int tileIndex) {
  if (terrainClass >= 0 && terrainClass < kClassCount) {
    g_currentTerrainAttempt.seed_candidate_tiles[terrainClass] = tileIndex;
  }
}

void RuntimeTerrainMapOracleFinishAttempt(int accepted, unsigned int mapLcg) {
  if (!g_currentTerrainAttempt.active || g_currentTerrainAttempt.rotation_column < 0) {
    return;
  }
  g_currentTerrainAttempt.map_lcg_after_validation = mapLcg;
  g_currentTerrainAttempt.accepted = accepted != 0;
  g_currentTerrainAttempt.active = false;

  EnsureTerrainAttemptCapacity(g_terrain, g_terrain.attempt_count + 1);
  g_terrain.attempts[g_terrain.attempt_count] = g_currentTerrainAttempt;
  // Ownership of coarse attempt storage transferred into the terrain attempt list.
  g_currentTerrainAttempt.coarse_generation.attempts = 0;
  g_currentTerrainAttempt.coarse_generation.attempt_count = 0;
  g_currentTerrainAttempt.coarse_generation.attempt_capacity = 0;
  ++g_terrain.attempt_count;
  g_terrain.final_map_lcg = mapLcg;
  ReplaceJson(g_serializedTerrain, SerializeTerrainTrace(g_terrain));
}

const JSON_Value* RuntimeTerrainMapOracleValue() {
  return g_serializedTerrain;
}

int RuntimeTerrainMapOracleTopologyByte() {
  return g_topologyByte;
}
