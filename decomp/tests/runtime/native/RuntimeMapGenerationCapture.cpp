#include "RuntimeMapGenerationCapture.h"

#include "JsonObject.h"
#include "RuntimeCoarseMapOracle.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include "game/globals/game_session_globals.h"
#include "game/map/TMapMgr.h"

void CaptureRuntimeMapGeneration(RuntimeRun& run) {
  if (run.RequestsCapture(kRuntimeCaptureCoarseMapGeneration) &&
      !run.HasCapture("coarse_map_generation")) {
    const JSON_Value* generation = RuntimeCoarseMapOracleValue();
    if (generation != 0) {
      run.SetCapture("coarse_map_generation", JsonDeepCopy(generation));
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
  JsonObject capture;
  capture.Set("scenario_tag", static_cast<LPCSTR>(g_pGlobalMapState->scenarioTagText));
  capture.Set("retail_topology", static_cast<unsigned int>(RuntimeTerrainMapOracleTopologyByte()));
  capture.Set("generation", JsonDeepCopy(generation));
  run.SetCapture("random_map_terrain", capture.Release());
}
