#include "RuntimeMapGenerationCapture.h"

#include "RuntimeCoarseMapOracle.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/globals/game_session_globals.h"
#include "game/map/TMapMgr.h"
#include "parson.h"

void CaptureRuntimeMapGeneration(RuntimeRun& run) {
  if (run.RequestsCapture(kRuntimeCaptureCoarseMapGeneration) &&
      !run.HasCapture("coarse_map_generation")) {
    const JSON_Value* generation = RuntimeCoarseMapOracleValue();
    if (generation != 0) {
      run.SetCapture("coarse_map_generation", json_value_deep_copy(generation));
    }
  }

  if (!run.RequestsCapture(kRuntimeCaptureRandomMapTerrain) ||
      run.HasCapture("random_map_terrain") || g_pGlobalMapState == 0) {
    return;
  }
  const JSON_Value* generation = RuntimeTerrainMapOracleValue();
  if (generation == 0) {
    return;
  }
  JSON_Value* value = json_value_init_object();
  JSON_Object* capture = json_value_get_object(value);
  json_object_set_string(capture, "scenario_tag",
                         static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText));
  json_object_set_number(capture, "retail_topology",
                         static_cast<double>(RuntimeTerrainMapOracleTopologyByte()));
  json_object_set_value(capture, "generation", json_value_deep_copy(generation));
  run.SetCapture("random_map_terrain", value);
}
