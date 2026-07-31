#include "RuntimeHeartbeat.h"

#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeRun.h"

#include "game/core/global_data_tables.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

#include <windows.h>
#include "game/globals/view_registries.h"

namespace {

CString SemanticFingerprint(RuntimeRun& run) {
  CString fingerprint;
  fingerprint.Format("%d|%s|%d|%s", g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1,
                     RuntimeClassName(RuntimeMainView()), g_ModalViewStack.GetCount(),
                     run.PhaseName());
  return fingerprint;
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
  CString json;
  json.Format("{\"phase\": \"%s\", \"last_action\": \"%s\", \"idle_ticks\": %lu, "
              "\"elapsed_ms\": %lu, \"turn_event\": %d, \"root_class\": \"%s\", "
              "\"modal_depth\": %d, \"progress_counter\": %lu, \"last_progress_ms\": %lu, "
              "\"hold\": %s, \"await\": %s}\n",
              run.PhaseName(), run.LastAction(), run.IdleTicks(), run.ElapsedMs(),
              g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1,
              RuntimeClassName(RuntimeMainView()), g_ModalViewStack.GetCount(),
              run.ProgressCounter(), run.LastProgressMs(), run.HoldRequested() ? "true" : "false",
              static_cast<LPCSTR>(RuntimeAwaitStateJson(run.AwaitState())));
  RuntimeJson::WriteFileAtomically(run.HeartbeatPath(), json);
}
