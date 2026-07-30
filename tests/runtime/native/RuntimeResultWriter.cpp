#include "RuntimeResultWriter.h"

#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"

#include "game/core/global_data_tables.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

bool WriteRuntimeResult(RuntimeRun& run, RuntimeScenario& scenario, const char* status,
                        const char* failureJson) {
  TView* mainView = RuntimeMainView();
  TGreatPower* activeNation = 0;
  TCity* activeCity = 0;
  if (g_pSimMgr != 0 && g_pSimMgr->activeNationSlot >= 0 && g_pSimMgr->activeNationSlot < 7) {
    activeNation = g_apNationStates[g_pSimMgr->activeNationSlot];
    if (activeNation != 0) {
      activeCity = activeNation->city;
    }
  }
  CString productionOrders("[");
  CString productionFlags("[");
  for (int slot = 0; slot < 0x10; ++slot) {
    CString value;
    value.Format("%s%d", slot == 0 ? "" : ", ",
                 activeCity != 0 ? activeCity->productionOrderTable1dc[slot] : -1);
    productionOrders += value;
    value.Format("%s%d", slot == 0 ? "" : ", ",
                 activeCity != 0 ? activeCity->productionFlags21c[slot] : -1);
    productionFlags += value;
  }
  productionOrders += ']';
  productionFlags += ']';
  // A scenario that fails while still waiting is the common case; publishing the armed
  // wait is what turns "stalled in phase X" into "waiting for Y, written at Z".
  CString awaitState(RuntimeAwaitStateJson(run.AwaitState()));
  // Only on a non-pass (or a deliberate hold): a passing run's tree is noise, but a failed
  // selector is precisely when an author needs the real tag hierarchy rather than a guess
  // read off a UI builder. `just runtime-tree` prints this.
  CString currentUiTree("null");
  if (lstrcmpA(status, "passed") != 0 || run.HoldRequested()) {
    currentUiTree = CaptureRuntimeCurrentUiTree();
  }
  CString eventSequence(run.ActivatedEventSequence());
  eventSequence += ']';
  CString handledModals(run.HandledModals());
  handledModals += ']';
  CString unexpectedModals(run.UnexpectedModals());
  unexpectedModals += ']';
  CString faults(run.Faults());
  faults += ']';
  CString actionLog(run.ActionLog());
  actionLog += ']';
  if (run.CapturesSnapshot(kRuntimeSnapshotUi) &&
      (run.RandomSetupUiSnapshot().IsEmpty() || run.StrategicMapUiSnapshot().IsEmpty())) {
    status = "failed";
    failureJson = "\"generated UI factory snapshot is missing\"";
    run.RecordAssertion("result.random_ui_snapshot.present", failureJson, true);
  }
  if (scenario.RequiresScenarioUiSnapshot() && run.ScenarioUiSnapshot().IsEmpty()) {
    status = "failed";
    failureJson = "\"scenario UI snapshot is missing\"";
    run.RecordAssertion("result.scenario_ui_snapshot.present", failureJson, true);
  }
  CString uiSnapshots("[");
  if (run.CapturesSnapshot(kRuntimeSnapshotUi)) {
    if (!run.RandomSetupUiSnapshot().IsEmpty()) {
      uiSnapshots += "\n";
      uiSnapshots += run.RandomSetupUiSnapshot();
    }
    if (!run.StrategicMapUiSnapshot().IsEmpty()) {
      if (!run.RandomSetupUiSnapshot().IsEmpty()) {
        uiSnapshots += ",";
      }
      uiSnapshots += "\n";
      uiSnapshots += run.StrategicMapUiSnapshot();
    }
    if (!run.ScenarioUiSnapshot().IsEmpty()) {
      if (!run.RandomSetupUiSnapshot().IsEmpty() || !run.StrategicMapUiSnapshot().IsEmpty()) {
        uiSnapshots += ",";
      }
      uiSnapshots += "\n";
      uiSnapshots += run.ScenarioUiSnapshot();
    }
    uiSnapshots += "\n  ";
  }
  uiSnapshots += "]";
  CString capitalConfirmationSnapshot("null");
  if (!run.CapitalConfirmationUiSnapshot().IsEmpty()) {
    capitalConfirmationSnapshot = run.CapitalConfirmationUiSnapshot();
  }
  CString mapState("null");
  if (!run.MapStateJson().IsEmpty()) {
    mapState = run.MapStateJson();
  }
  CString roundtrip("null");
  if (!run.SerializationRoundtripJson().IsEmpty()) {
    roundtrip = run.SerializationRoundtripJson();
  }
  CString assertions = run.AssertionFailuresJson();
  CString assertionId("null");
  if (run.FirstAssertionId()[0] != 0) {
    assertionId.Empty();
    RuntimeJson::AppendString(assertionId, run.FirstAssertionId());
  }
  CString json;
  json.Format("{\n"
              "  \"format_version\": 1,\n"
              "  \"name\": \"%s\",\n"
              "  \"evidence_kind\": \"%s\",\n"
              "  \"status\": \"%s\",\n"
              "  \"seed\": %u,\n"
              "  \"idle_ticks\": %lu,\n"
              "  \"elapsed_ms\": %lu,\n"
              "  \"phase\": \"%s\",\n"
              "  \"last_action\": \"%s\",\n"
              "  \"await\": %s,\n"
              "  \"current_ui_tree\": %s,\n"
              "  \"event_sequence\": %s,\n"
              "  \"actions\": %s,\n"
              "  \"ui_snapshots\": %s,\n"
              "  \"capital_confirmation_snapshot\": %s,\n"
              "  \"map_state\": %s,\n"
              "  \"serialization_roundtrip\": %s,\n"
              "  \"assertion_id\": %s,\n"
              "  \"assertions\": %s,\n"
              "  \"state\": {\n"
              "    \"turn_event\": %d,\n"
              "    \"root_class\": \"%s\",\n"
              "    \"active_nation\": %d,\n"
              "    \"selected_nation\": %d,\n"
              "    \"economic_turn\": %d,\n"
              "    \"city_present\": %s,\n"
              "    \"production_orders\": %s,\n"
              "    \"production_flags\": %s,\n"
              "    \"difficulty\": %d,\n"
              "    \"multiplayer_role\": %d,\n"
              "    \"turn_state\": %d,\n"
              "    \"mode\": %d,\n"
              "    \"global_map\": %s,\n"
              "    \"display_manager\": %s,\n"
              "    \"global_ui_root\": %s,\n"
              "    \"simulation_manager\": %s,\n"
              "    \"ui_runtime_context\": %s,\n"
              "    \"ui_view_manager\": %s\n"
              "  },\n"
              "  \"runtime\": {\n"
              "    \"faults\": %s,\n"
              "    \"handled_modals\": %s,\n"
              "    \"unexpected_modals\": %s\n"
              "  },\n"
              "  \"failure\": %s\n"
              "}\n",
              run.TestName(), run.EvidenceKind(), status, run.Seed(), run.IdleTicks(),
              run.ElapsedMs(), run.PhaseName(), run.LastAction(), static_cast<LPCSTR>(awaitState),
              static_cast<LPCSTR>(currentUiTree), static_cast<LPCSTR>(eventSequence),
              static_cast<LPCSTR>(actionLog), static_cast<LPCSTR>(uiSnapshots),
              static_cast<LPCSTR>(capitalConfirmationSnapshot), static_cast<LPCSTR>(mapState),
              static_cast<LPCSTR>(roundtrip), static_cast<LPCSTR>(assertionId),
              static_cast<LPCSTR>(assertions),
              g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1, RuntimeClassName(mainView),
              g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1, run.SelectedNationSlot(),
              g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1, activeCity != 0 ? "true" : "false",
              static_cast<LPCSTR>(productionOrders), static_cast<LPCSTR>(productionFlags),
              g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1,
              g_pSimMgr != 0 ? g_pSimMgr->multiplayerSessionRole : -1,
              g_pSimMgr != 0 ? g_pSimMgr->turnStateCode : -1, g_pSimMgr != 0 ? g_pSimMgr->mode : -1,
              g_pGlobalMapState != 0 ? "true" : "false", g_pDisplayMgr != 0 ? "true" : "false",
              g_pAmbitApplication != 0 ? "true" : "false", g_pSimMgr != 0 ? "true" : "false",
              g_pViewMgr != 0 ? "true" : "false", g_pAssetMgr != 0 ? "true" : "false",
              static_cast<LPCSTR>(faults), static_cast<LPCSTR>(handledModals),
              static_cast<LPCSTR>(unexpectedModals), failureJson);
  return RuntimeJson::WriteFileAtomically(run.ResultPath(), json);
}
