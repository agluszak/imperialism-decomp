#include "RuntimeHeartbeat.h"

#include "RuntimeObservations.h"
#include "RuntimeRun.h"

#include "game/core/global_data_tables.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

#include <string.h>
#include "game/globals/view_registries.h"

namespace {

CString SemanticFingerprint(RuntimeRun& run) {
  CString fingerprint;
  fingerprint.Format("%d|%s|%d|%s", g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1,
                     RuntimeClassName(RuntimeMainView()), g_ModalViewStack.GetCount(),
                     run.PhaseName());
  return fingerprint;
}

JSON_Value* BuildAwaitState(const RuntimeAwaitState& state) {
  if (!state.IsArmed()) {
    return json_value_init_null();
  }
  char observations[256];
  DescribeRuntimeObservationMask(state.ObservationKinds(), observations, sizeof(observations));
  JSON_Value* value = json_value_init_object();
  JSON_Object* await = value != 0 ? json_value_get_object(value) : 0;
  if (await == 0 ||
      json_object_set_string(await, "expression", state.Expression()) != JSONSuccess ||
      json_object_set_string(await, "source", state.Source()) != JSONSuccess ||
      json_object_set_string(await, "observations", observations) != JSONSuccess ||
      json_object_set_number(await, "observation_mask", state.ObservationKinds()) != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

bool WriteJsonValueAtomically(const char* path, JSON_Value* value) {
  char* text = value != 0 ? json_serialize_to_string(value) : 0;
  if (text == 0) {
    return false;
  }
  bool written = WriteRuntimeBytesAtomically(path, text, static_cast<unsigned long>(strlen(text)));
  json_free_serialized_string(text);
  return written;
}

} // namespace

void WriteRuntimeHeartbeat(RuntimeRun& run) {
  if (run.HeartbeatPath()[0] == 0) {
    return;
  }
  unsigned long now = GetTickCount();
  CString fingerprint = SemanticFingerprint(run);
  if (fingerprint != run.LastFingerprint()) {
    run.LastFingerprint() = fingerprint;
    run.MarkFallbackProgress();
  }
  if (!run.HeartbeatDue(now, 250)) {
    return;
  }
  run.SetLastHeartbeatMs(now);

  JSON_Value* value = json_value_init_object();
  JSON_Object* heartbeat = value != 0 ? json_value_get_object(value) : 0;
  JSON_Value* await = BuildAwaitState(run.AwaitState());
  if (heartbeat == 0 || await == 0 ||
      json_object_set_string(heartbeat, "phase", run.PhaseName()) != JSONSuccess ||
      json_object_set_string(heartbeat, "last_action", run.LastAction()) != JSONSuccess ||
      json_object_set_number(heartbeat, "idle_ticks", run.IdleTicks()) != JSONSuccess ||
      json_object_set_number(heartbeat, "elapsed_ms", run.ElapsedMs()) != JSONSuccess ||
      json_object_set_number(heartbeat, "turn_event",
                             g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1) !=
          JSONSuccess ||
      json_object_set_string(heartbeat, "root_class", RuntimeClassName(RuntimeMainView())) !=
          JSONSuccess ||
      json_object_set_number(heartbeat, "modal_depth", g_ModalViewStack.GetCount()) !=
          JSONSuccess ||
      json_object_set_number(heartbeat, "progress_counter", run.ProgressCounter()) != JSONSuccess ||
      json_object_set_number(heartbeat, "last_progress_ms", run.LastProgressMs()) != JSONSuccess ||
      json_object_set_boolean(heartbeat, "hold", run.HoldRequested()) != JSONSuccess) {
    json_value_free(await);
    json_value_free(value);
    return;
  }
  if (json_object_set_value(heartbeat, "await", await) != JSONSuccess) {
    json_value_free(await);
    json_value_free(value);
    return;
  }
  WriteJsonValueAtomically(run.HeartbeatPath(), value);
  json_value_free(value);
}
