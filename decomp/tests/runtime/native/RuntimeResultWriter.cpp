#include "RuntimeResultWriter.h"

#include "RuntimeObservations.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"

#include <string.h>

namespace {

JSON_Value* CopyValue(JSON_Value* value) {
  return value != 0 ? json_value_deep_copy(value) : json_value_init_null();
}

bool SetOwnedValue(JSON_Object* object, const char* name, JSON_Value*& value) {
  if (object == 0 || value == 0 || json_object_set_value(object, name, value) != JSONSuccess) {
    return false;
  }
  value = 0;
  return true;
}

void AppendSnapshot(JSON_Array* snapshots, JSON_Value* snapshot) {
  JSON_Value* copy = CopyValue(snapshot);
  if (copy != 0 && json_array_append_value(snapshots, copy) != JSONSuccess) {
    json_value_free(copy);
  }
}

JSON_Value* BuildUiTreeCapture(RuntimeRun& run, bool includeCurrentTree) {
  JSON_Value* value = json_value_init_object();
  JSON_Object* uiTree = value != 0 ? json_value_get_object(value) : 0;
  JSON_Value* snapshotsValue = json_value_init_array();
  JSON_Array* snapshots = snapshotsValue != 0 ? json_value_get_array(snapshotsValue) : 0;
  if (uiTree == 0 || snapshots == 0) {
    json_value_free(snapshotsValue);
    json_value_free(value);
    return 0;
  }
  if (run.RandomSetupUiSnapshot() != 0) {
    AppendSnapshot(snapshots, run.RandomSetupUiSnapshot());
  }
  if (run.StrategicMapUiSnapshot() != 0) {
    AppendSnapshot(snapshots, run.StrategicMapUiSnapshot());
  }
  if (run.ScenarioUiSnapshot() != 0) {
    AppendSnapshot(snapshots, run.ScenarioUiSnapshot());
  }
  JSON_Value* current = includeCurrentTree ? CaptureRuntimeCurrentUiTree() : json_value_init_null();
  JSON_Value* capital = CopyValue(run.CapitalConfirmationUiSnapshot());
  if (current == 0 || capital == 0 || !SetOwnedValue(uiTree, "snapshots", snapshotsValue) ||
      !SetOwnedValue(uiTree, "current", current) ||
      !SetOwnedValue(uiTree, "capital_confirmation", capital)) {
    json_value_free(snapshotsValue);
    json_value_free(current);
    json_value_free(capital);
    json_value_free(value);
    return 0;
  }
  return value;
}

bool WriteJsonValueAtomically(const char* path, JSON_Value* value) {
  char* text = value != 0 ? json_serialize_to_string_pretty(value) : 0;
  if (text == 0) {
    return false;
  }
  bool written = WriteRuntimeBytesAtomically(path, text, static_cast<unsigned long>(strlen(text)));
  json_free_serialized_string(text);
  return written;
}

void RecordMissingCapture(RuntimeRun& run, const char* assertionId, const char* failure,
                          const char*& status) {
  status = "failed";
  run.RecordAssertion(assertionId, failure, true);
}

} // namespace

bool WriteRuntimeResult(RuntimeRun& run, const char* status) {
  const char* resultStatus = status != 0 ? status : "failed";

  if (run.RequestsCapture(kRuntimeCaptureUiTree) &&
      (!run.HasRandomSetupUiSnapshot() || !run.HasStrategicMapUiSnapshot())) {
    RecordMissingCapture(run, "result.random_ui_snapshot.present",
                         "generated UI factory snapshot is missing", resultStatus);
  }
  if (run.CapturesAnyUiTree() && !run.HasScenarioUiSnapshot()) {
    RecordMissingCapture(run, "result.scenario_ui_snapshot.present",
                         "scenario UI snapshot is missing", resultStatus);
  }
  if (run.RequestsCapture(kRuntimeCaptureMapState) && !run.HasCapture("map_state")) {
    RecordMissingCapture(run, "result.map_state.present", "map-state capture is missing",
                         resultStatus);
  }
  if (run.RequestsCapture(kRuntimeCaptureGameState) && !run.HasCapture("game_state")) {
    RecordMissingCapture(run, "result.game_state.present", "game-state capture is missing",
                         resultStatus);
  }
  if (run.RequestsCapture(kRuntimeCaptureCoarseMapGeneration) &&
      !run.HasCapture("coarse_map_generation")) {
    RecordMissingCapture(run, "result.coarse_map_generation.present",
                         "coarse-map-generation capture is missing", resultStatus);
  }
  if (run.RequestsCapture(kRuntimeCaptureRandomMapTerrain) &&
      !run.HasCapture("random_map_terrain")) {
    RecordMissingCapture(run, "result.random_map_terrain.present",
                         "random-map-terrain capture is missing", resultStatus);
  }

  bool needsUiTree = run.RequestsCapture(kRuntimeCaptureUiTree) || run.CapturesAnyUiTree() ||
                     lstrcmpA(resultStatus, "passed") != 0 || run.HoldRequested();
  if (needsUiTree) {
    JSON_Value* uiTree =
        BuildUiTreeCapture(run, lstrcmpA(resultStatus, "passed") != 0 || run.HoldRequested());
    if (uiTree != 0) {
      run.SetCapture("ui_tree", uiTree);
    }
  }

  JSON_Value* rootValue = json_value_init_object();
  JSON_Object* root = rootValue != 0 ? json_value_get_object(rootValue) : 0;
  JSON_Value* captures =
      CopyValue(run.Captures() != 0 ? json_object_get_wrapping_value(run.Captures()) : 0);
  if (root == 0 || captures == 0 ||
      json_object_set_string(root, "name", run.TestName()) != JSONSuccess ||
      json_object_set_number(root, "seed", run.Seed()) != JSONSuccess ||
      json_object_set_string(root, "status", resultStatus) != JSONSuccess ||
      !SetOwnedValue(root, "captures", captures)) {
    json_value_free(captures);
    json_value_free(rootValue);
    return false;
  }
  bool written = WriteJsonValueAtomically(run.ResultPath(), rootValue);
  json_value_free(rootValue);
  return written;
}
