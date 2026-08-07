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
