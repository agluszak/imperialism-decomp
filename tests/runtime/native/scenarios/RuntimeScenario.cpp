#include "RuntimeScenario.h"
#include "RuntimeHarness.h"
#include "RuntimeContext.h"
#include "RuntimeDebuggerTrap.h"
#include "RuntimeUiDriver.h"
#include "screens/MainMenuDriver.h"
#include "screens/RandomSetupDriver.h"

#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/CIncludeView.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/TControl.h"
#include "game/map_ui/TCitySiteView.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/CMcEditWindow.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_screens/TGameSetupPicture.h"
#include "game/ImperialismApp.h"
#include "game/map/TMapUberPicture.h"
#include "game/map/TMapMgr.h"
#include "game/navy_ui/TOceanDialog.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TRadioTextCluster.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/core/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/ui_tags_screens.h"
#include "game/ui_tags_widgets.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

namespace {

typedef void (*RuntimeStep)();

void RunWaitingForManagers();
void RunScenarioOwnedStep();
void RunWaitingForMainMenu();
void RunWaitingForRandomSetup();
void RunSettingCountryName();
void RunSelectingDifficulty();
void RunActivatingOkay();
void RunWaitingForEasyStrategicMap();
void RunWaitingForStrategicMap();
void RunVerifyingStrategicMap();
void RunWaitingForModalDismissal();
void RunPrimingMapHover();
void RunDispatchingMapHotkey();
void RunExercisingMapHover();
void RunReturningToRandomSetup();
void RunReturningToMainMenu();
void RunReenteringRandomSetup();
void RunVerifyingReturnedRandomSetup();
void RunWaitingForSecondCitySite();
void RunWaitingForSecondPromptDismissal();
void RunWaitingForCitySiteConfirmation();
void RunWaitingForCombinedMap();
void RunVerifyingCombinedMapExtents();

struct RuntimeTestState {
  RuntimeScenario* scenario;
  RuntimeStep step;
  const char* phaseName;
  bool finished;
  unsigned int seed;
  unsigned long idleTicks;
  unsigned long phaseTicks;
  unsigned long startMs;
  unsigned long phaseStartMs;
  unsigned long lastHeartbeatMs;
  unsigned long progressCounter;
  unsigned long lastProgressMs;
  short selectedNationSlot;
  HWND mainWindowHandle;
  bool newspaperAdvanced;
  char resultPath[MAX_PATH];
  char heartbeatPath[MAX_PATH];
  char debugRecordPath[MAX_PATH];
  char fixturePath[MAX_PATH];
  char lastAction[64];
};

RuntimeTestState g_runtimeTestState = {0,  0, "not_started", false, 1,  0,  0,  0, 0, 0, 0, 0,
                                       -1, 0, false,         "",    "", "", "", ""};
CString g_randomSetupUiSnapshot;
CString g_strategicMapUiSnapshot;
CString g_cityUiSnapshot;
CString g_capitalConfirmationUiSnapshot;
CString g_activatedEventSequence("[");
CString g_handledModals("[");
CString g_unexpectedModals("[");
CString g_faults("[");
CString g_actionLog("[");
CString g_lastFingerprint;
CString g_mapStateJson;

// Easy-difficulty kinds share the setup flow (dif1 click, no capital pick).
RuntimeScenario& ActiveScenario() {
  return *g_runtimeTestState.scenario;
}

bool IsEasyStyleTest() {
  return ActiveScenario().UsesEasyDifficulty();
}

bool IsRandomGameTest() {
  return ActiveScenario().UsesRandomGameFlow();
}

// Kinds whose runs end on a live map and want the normalized simulation
// snapshot + activated-event sequence in the result.
bool RecordsGameFlow() {
  return ActiveScenario().RecordsGameFlow();
}

const char* TestName() {
  return ActiveScenario().Name();
}

const char* PhaseName() {
  return g_runtimeTestState.phaseName;
}

void AppendJsonArrayItem(CString& array, const CString& item) {
  if (array.GetLength() > 1) {
    array += ", ";
  }
  array += item;
}

void RecordAction(const char* action) {
  lstrcpynA(g_runtimeTestState.lastAction, action, sizeof(g_runtimeTestState.lastAction));
  CString entry;
  entry.Format("{\"t_ms\": %lu, \"phase\": \"%s\", \"action\": \"%s\"}",
               GetTickCount() - g_runtimeTestState.startMs, PhaseName(), action);
  AppendJsonArrayItem(g_actionLog, entry);
}

void SetStep(RuntimeStep step, const char* phaseName, const char* action) {
  g_runtimeTestState.step = step;
  g_runtimeTestState.phaseName = phaseName;
  g_runtimeTestState.phaseTicks = 0;
  g_runtimeTestState.phaseStartMs = GetTickCount();
  RecordAction(action);
}

bool RequiredManagersAreInitialized() {
  return g_pGlobalUiRootController != 0 && g_pSimMgr != 0 && g_pUiRuntimeContext != 0 &&
         g_pDisplayMgr != 0 && g_pUiViewManager != 0;
}

TView* MainView() {
  if (g_pDisplayMgr == 0 || g_pDisplayMgr->activeDialog == 0) {
    return 0;
  }
  return g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
}

const char* RuntimeClassName(TView* view) {
  if (view == 0) {
    return "";
  }
  CRuntimeClass* runtimeClass = view->GetRuntimeClass();
  if (runtimeClass == 0 || runtimeClass->m_lpszClassName == 0) {
    return "";
  }
  return runtimeClass->m_lpszClassName;
}

bool IsViewKindOf(TView* view, CRuntimeClass* runtimeClass) {
  return view != 0 && view->IsKindOf(runtimeClass) != 0;
}

void RequestAnotherDriverTick() {
  PostThreadMessageA(GetCurrentThreadId(), WM_NULL, 0, 0);
}

void RequestGameClose() {
  if (g_runtimeTestState.mainWindowHandle != 0) {
    PostMessageA(g_runtimeTestState.mainWindowHandle, WM_CLOSE, 0, 0);
  } else {
    PostQuitMessage(0);
  }
}

bool WriteAll(HANDLE file, const char* bytes, DWORD size) {
  DWORD written = 0;
  return WriteFile(file, bytes, size, &written, 0) != 0 && written == size;
}

bool WriteFileAtomically(const char* path, const CString& json) {
  CString temporaryPath(path);
  temporaryPath += ".tmp";
  HANDLE file =
      CreateFileA(temporaryPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  const char* bytes = static_cast<LPCSTR>(json);
  bool wrote = WriteAll(file, bytes, static_cast<DWORD>(json.GetLength()));
  if (wrote) {
    wrote = FlushFileBuffers(file) != 0;
  }
  CloseHandle(file);
  if (!wrote) {
    DeleteFileA(temporaryPath);
    return false;
  }
  if (MoveFileExA(temporaryPath, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    DeleteFileA(temporaryPath);
    return false;
  }
  return true;
}

void AppendJsonString(CString& json, const char* value) {
  json += '"';
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor != 0;
       ++cursor) {
    char escaped[7];
    switch (*cursor) {
    case '"':
      json += "\\\"";
      break;
    case '\\':
      json += "\\\\";
      break;
    case '\n':
      json += "\\n";
      break;
    case '\r':
      json += "\\r";
      break;
    case '\t':
      json += "\\t";
      break;
    default:
      if (*cursor < 0x20) {
        wsprintfA(escaped, "\\u%04x", static_cast<unsigned int>(*cursor));
        json += escaped;
      } else {
        json += static_cast<char>(*cursor);
      }
      break;
    }
  }
  json += '"';
}

void FourCcText(unsigned int tag, char text[5]) {
  text[0] = static_cast<char>(tag >> 24);
  text[1] = static_cast<char>(tag >> 16);
  text[2] = static_cast<char>(tag >> 8);
  text[3] = static_cast<char>(tag);
  text[4] = 0;
}

int TagOccurrenceBefore(TView* parent, TView* target) {
  if (parent == 0 || parent->childList44 == 0) {
    return 1;
  }
  int occurrence = 1;
  POSITION position = parent->childList44->GetHeadPosition();
  while (position != 0) {
    TView* sibling = parent->childList44->GetNext(position);
    if (sibling == target) {
      break;
    }
    if (sibling->controlTag == target->controlTag) {
      ++occurrence;
    }
  }
  return occurrence;
}

CString ViewPath(TView* view, const CString& parentPath) {
  CString path;
  path.Format("%08x#%d", static_cast<unsigned int>(view->controlTag),
              TagOccurrenceBefore(view->ownerContext, view));
  if (!parentPath.IsEmpty()) {
    path = parentPath + "/" + path;
  }
  return path;
}

void AppendViewTreeNodes(CString& json, TView* view, const CString& parentPath, bool& firstNode) {
  if (view == 0) {
    return;
  }
  CString path = ViewPath(view, parentPath);
  char tag[5];
  FourCcText(static_cast<unsigned int>(view->controlTag), tag);
  if (!firstNode) {
    json += ",\n";
  }
  firstNode = false;
  json += "      {\"path\": ";
  AppendJsonString(json, path);
  json += ", \"parent\": ";
  if (parentPath.IsEmpty()) {
    json += "null";
  } else {
    AppendJsonString(json, parentPath);
  }
  json += ", \"tag\": ";
  AppendJsonString(json, tag);
  json += ", \"class\": ";
  AppendJsonString(json, RuntimeClassName(view));
  CString fields;
  fields.Format(", \"bounds\": [%d, %d, %d, %d], \"absolute\": [%d, %d], \"state\": %d, "
                "\"enabled\": %d, \"control_value\": %d",
                view->ownerLocalX, view->ownerLocalY, view->frameWidth34, view->frameHeight38,
                view->absoluteX, view->absoluteY, view->field04, view->field08,
                view->controlValue3c);
  json += fields;
  if (view->IsKindOf(RUNTIME_CLASS(TPicture)) != 0) {
    TPicture* picture = static_cast<TPicture*>(view);
    fields.Format(", \"picture_id\": %d", static_cast<int>(picture->glyphBase84));
    json += fields;
  }
  if (view->IsKindOf(RUNTIME_CLASS(TStaticText)) != 0) {
    TStaticText* text = static_cast<TStaticText*>(view);
    json += ", \"text\": ";
    AppendJsonString(json, text->text != 0 ? static_cast<LPCSTR>(*text->text) : "");
  }
  json += "}";

  if (view->childList44 == 0) {
    return;
  }
  POSITION position = view->childList44->GetHeadPosition();
  while (position != 0) {
    TView* child = view->childList44->GetNext(position);
    AppendViewTreeNodes(json, child, path, firstNode);
  }
}

CString CaptureUiSnapshot(int eventCode, TView* root) {
  CString json;
  CString header;
  header.Format("    {\"event\": %d, \"nodes\": [\n", eventCode);
  json += header;
  bool firstNode = true;
  AppendViewTreeNodes(json, root, CString(), firstNode);
  json += "\n    ]}";
  return json;
}

bool HoldRequested() {
  static bool resolved = false;
  static bool hold = false;
  if (!resolved) {
    resolved = true;
    char value[16];
    hold = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_HOLD", value, sizeof(value)) != 0;
  }
  return hold;
}

// Debug hook for the host runner's liveness classification: name a phase in
// IMPERIALISM_RUNTIME_TEST_SPIN and the driver keeps pumping/heartbeating in
// that phase without making semantic progress or enforcing its own deadline.
bool SpinRequestedForCurrentPhase() {
  static bool resolved = false;
  static char spinPhase[48];
  if (!resolved) {
    resolved = true;
    if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_SPIN", spinPhase, sizeof(spinPhase)) ==
        0) {
      spinPhase[0] = 0;
    }
  }
  return spinPhase[0] != 0 && lstrcmpiA(spinPhase, PhaseName()) == 0;
}

bool WriteResultFile(const char* status, const char* failure) {
  TView* mainView = MainView();
  CString eventSequence(g_activatedEventSequence);
  eventSequence += ']';
  CString handledModals(g_handledModals);
  handledModals += ']';
  CString unexpectedModals(g_unexpectedModals);
  unexpectedModals += ']';
  CString faults(g_faults);
  faults += ']';
  CString actionLog(g_actionLog);
  actionLog += ']';
  if (IsRandomGameTest() &&
      (g_randomSetupUiSnapshot.IsEmpty() || g_strategicMapUiSnapshot.IsEmpty())) {
    status = "failed";
    failure = "\"generated UI factory snapshot is missing\"";
  }
  if (ActiveScenario().RequiresCityUiSnapshot() && g_cityUiSnapshot.IsEmpty()) {
    status = "failed";
    failure = "\"city production UI snapshot is missing\"";
  }
  CString uiSnapshots("[");
  if (IsRandomGameTest()) {
    if (!g_randomSetupUiSnapshot.IsEmpty()) {
      uiSnapshots += "\n";
      uiSnapshots += g_randomSetupUiSnapshot;
    }
    if (!g_strategicMapUiSnapshot.IsEmpty()) {
      if (!g_randomSetupUiSnapshot.IsEmpty()) {
        uiSnapshots += ",";
      }
      uiSnapshots += "\n";
      uiSnapshots += g_strategicMapUiSnapshot;
    }
    if (!g_cityUiSnapshot.IsEmpty()) {
      if (!g_randomSetupUiSnapshot.IsEmpty() || !g_strategicMapUiSnapshot.IsEmpty()) {
        uiSnapshots += ",";
      }
      uiSnapshots += "\n";
      uiSnapshots += g_cityUiSnapshot;
    }
    uiSnapshots += "\n  ";
  }
  uiSnapshots += "]";
  CString capitalConfirmationSnapshot("null");
  if (!g_capitalConfirmationUiSnapshot.IsEmpty()) {
    capitalConfirmationSnapshot = g_capitalConfirmationUiSnapshot;
  }
  CString mapState("null");
  if (!g_mapStateJson.IsEmpty()) {
    mapState = g_mapStateJson;
  }
  CString json;
  json.Format("{\n"
              "  \"format_version\": 1,\n"
              "  \"name\": \"%s\",\n"
              "  \"status\": \"%s\",\n"
              "  \"seed\": %u,\n"
              "  \"idle_ticks\": %lu,\n"
              "  \"elapsed_ms\": %lu,\n"
              "  \"phase\": \"%s\",\n"
              "  \"last_action\": \"%s\",\n"
              "  \"event_sequence\": %s,\n"
              "  \"actions\": %s,\n"
              "  \"ui_snapshots\": %s,\n"
              "  \"capital_confirmation_snapshot\": %s,\n"
              "  \"map_state\": %s,\n"
              "  \"state\": {\n"
              "    \"turn_event\": %d,\n"
              "    \"root_class\": \"%s\",\n"
              "    \"active_nation\": %d,\n"
              "    \"selected_nation\": %d,\n"
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
              TestName(), status, g_runtimeTestState.seed, g_runtimeTestState.idleTicks,
              GetTickCount() - g_runtimeTestState.startMs, PhaseName(),
              g_runtimeTestState.lastAction, static_cast<LPCSTR>(eventSequence),
              static_cast<LPCSTR>(actionLog), static_cast<LPCSTR>(uiSnapshots),
              static_cast<LPCSTR>(capitalConfirmationSnapshot), static_cast<LPCSTR>(mapState),
              g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1,
              RuntimeClassName(mainView), g_pSimMgr != 0 ? g_pSimMgr->activeNationSlot : -1,
              g_runtimeTestState.selectedNationSlot,
              g_pSimMgr != 0 ? g_pSimMgr->difficultyLevel : -1,
              g_pSimMgr != 0 ? g_pSimMgr->multiplayerSessionRole : -1,
              g_pSimMgr != 0 ? g_pSimMgr->turnStateCode : -1, g_pSimMgr != 0 ? g_pSimMgr->mode : -1,
              g_pGlobalMapState != 0 ? "true" : "false", g_pDisplayMgr != 0 ? "true" : "false",
              g_pGlobalUiRootController != 0 ? "true" : "false", g_pSimMgr != 0 ? "true" : "false",
              g_pUiRuntimeContext != 0 ? "true" : "false", g_pUiViewManager != 0 ? "true" : "false",
              static_cast<LPCSTR>(faults), static_cast<LPCSTR>(handledModals),
              static_cast<LPCSTR>(unexpectedModals), failure);

  return WriteFileAtomically(g_runtimeTestState.resultPath, json);
}

void CaptureMapStateSnapshot();

void TrapDebugger(RuntimeDebugReason reason, const char* failure, EXCEPTION_POINTERS* exception) {
  TView* activeModal =
      g_ModalViewStack.IsEmpty() ? 0 : static_cast<TView*>(g_ModalViewStack.GetHead());
  RuntimeDebugRecord record;
  record.reason = reason;
  record.elapsedMs = GetTickCount() - g_runtimeTestState.startMs;
  record.testName = TestName();
  record.phase = PhaseName();
  record.lastAction = g_runtimeTestState.lastAction;
  record.turnEvent = g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1;
  record.modalDepth = g_ModalViewStack.GetCount();
  record.mainView = MainView();
  record.activeModal = activeModal;
  record.simMgr = g_pSimMgr;
  record.exceptionPointers = exception;

  if (g_runtimeTestState.debugRecordPath[0] != 0) {
    CString exceptionJson("null");
    if (exception != 0 && exception->ExceptionRecord != 0) {
      exceptionJson.Format("{\"code\": \"0x%08lx\", \"address\": \"%p\"}",
                           exception->ExceptionRecord->ExceptionCode,
                           exception->ExceptionRecord->ExceptionAddress);
    }
    CString json;
    json.Format("{\"reason\": %d, \"test\": \"%s\", \"phase\": \"%s\", "
                "\"last_action\": \"%s\", \"elapsed_ms\": %lu, \"turn_event\": %d, "
                "\"modal_depth\": %d, \"failure\": %s, \"exception\": %s}\n",
                static_cast<int>(reason), TestName(), PhaseName(), g_runtimeTestState.lastAction,
                record.elapsedMs, record.turnEvent, record.modalDepth, failure,
                static_cast<LPCSTR>(exceptionJson));
    WriteFileAtomically(g_runtimeTestState.debugRecordPath, json);
  }
  ImperialismRuntimeDebuggerTrap(&record);
}

void Finish(const char* status, const char* failure) {
  g_runtimeTestState.finished = true;
  g_runtimeTestState.step = 0;
  g_runtimeTestState.phaseName = "finished";
  if (RecordsGameFlow() && lstrcmpA(status, "passed") == 0) {
    CaptureMapStateSnapshot();
  }
  if (!WriteResultFile(status, failure)) {
    OutputDebugStringA("Imperialism runtime test could not write its result file.\n");
  }
  if (HoldRequested()) {
    return;
  }
  RequestGameClose();
}

void Fail(const char* failure) {
  TrapDebugger(kRuntimeDebugSemanticFailure, failure, 0);
  Finish("failed", failure);
}

unsigned long PhaseTimeoutMs() {
  static unsigned long timeoutMs = 0;
  if (timeoutMs == 0) {
    timeoutMs = 60000;
    char text[16];
    if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_PHASE_TIMEOUT_MS", text, sizeof(text)) !=
        0) {
      unsigned long parsed = strtoul(text, 0, 10);
      if (parsed != 0) {
        timeoutMs = parsed;
      }
    }
  }
  return timeoutMs;
}

bool WaitForNextTickOrTimeout(const char* failure) {
  if (GetTickCount() - g_runtimeTestState.phaseStartMs >= PhaseTimeoutMs()) {
    Fail(failure);
    return false;
  }
  RequestAnotherDriverTick();
  return true;
}

void RecordHandledModal(const char* label) {
  CString entry;
  entry.Format("\"%s\"", label);
  AppendJsonArrayItem(g_handledModals, entry);
}

void RecordUnexpectedModal(TView* modal) {
  char tag[5];
  FourCcText(static_cast<unsigned int>(modal->controlTag), tag);
  CString entry;
  entry.Format("{\"class\": \"%s\", \"tag\": \"%s\", \"phase\": \"%s\", \"t_ms\": %lu}",
               RuntimeClassName(modal), tag, PhaseName(),
               GetTickCount() - g_runtimeTestState.startMs);
  AppendJsonArrayItem(g_unexpectedModals, entry);
}

CString SemanticFingerprint() {
  CString fingerprint;
  fingerprint.Format("%d|%s|%d|%s",
                     g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1,
                     RuntimeClassName(MainView()), g_ModalViewStack.GetCount(), PhaseName());
  return fingerprint;
}

void MaybeWriteHeartbeat() {
  if (g_runtimeTestState.heartbeatPath[0] == 0) {
    return;
  }
  unsigned long now = GetTickCount();
  CString fingerprint = SemanticFingerprint();
  if (fingerprint != g_lastFingerprint) {
    g_lastFingerprint = fingerprint;
    ++g_runtimeTestState.progressCounter;
    g_runtimeTestState.lastProgressMs = now - g_runtimeTestState.startMs;
  }
  if (g_runtimeTestState.lastHeartbeatMs != 0 && now - g_runtimeTestState.lastHeartbeatMs < 250) {
    return;
  }
  g_runtimeTestState.lastHeartbeatMs = now;
  CString json;
  json.Format("{\"phase\": \"%s\", \"last_action\": \"%s\", \"idle_ticks\": %lu, "
              "\"elapsed_ms\": %lu, \"turn_event\": %d, \"root_class\": \"%s\", "
              "\"modal_depth\": %d, \"progress_counter\": %lu, \"last_progress_ms\": %lu, "
              "\"hold\": %s}\n",
              PhaseName(), g_runtimeTestState.lastAction, g_runtimeTestState.idleTicks,
              now - g_runtimeTestState.startMs,
              g_pUiRuntimeContext != 0 ? g_pUiRuntimeContext->currentTurnEventCode : -1,
              RuntimeClassName(MainView()), g_ModalViewStack.GetCount(),
              g_runtimeTestState.progressCounter, g_runtimeTestState.lastProgressMs,
              HoldRequested() ? "true" : "false");
  WriteFileAtomically(g_runtimeTestState.heartbeatPath, json);
}

// Seed-stable normalized simulation snapshot for the host-side map oracle:
// per-terrain-kind tile counts, per-nation owned-tile counts, and a few
// derived scalars. Captured at Finish for the random-game family.
void CaptureMapStateSnapshot() {
  if (g_pGlobalMapState == 0) {
    return;
  }
  long terrainCounts[kStrategicTerrainCount + 1]; // [+1] = unassigned/other
  long ownedTiles[7];
  memset(terrainCounts, 0, sizeof(terrainCounts));
  memset(ownedTiles, 0, sizeof(ownedTiles));
  for (short tile = 0; tile < 0x1950; ++tile) {
    const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
    int kind = static_cast<int>(terrain.GetTerrainKind());
    if (kind < 0 || kind >= kStrategicTerrainCount) {
      kind = kStrategicTerrainCount;
    }
    ++terrainCounts[kind];
    short owner = terrain.ownerNationTag04;
    if (owner >= 0 && owner < 7) {
      ++ownedTiles[owner];
    }
  }
  CString terrainJson("[");
  CString item;
  for (int kindIndex = 0; kindIndex <= kStrategicTerrainCount; ++kindIndex) {
    item.Format("%s%ld", kindIndex == 0 ? "" : ", ", terrainCounts[kindIndex]);
    terrainJson += item;
  }
  terrainJson += "]";
  CString ownedJson("[");
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    item.Format("%s%ld", nationSlot == 0 ? "" : ", ", ownedTiles[nationSlot]);
    ownedJson += item;
  }
  ownedJson += "]";
  g_mapStateJson.Format("{\"terrain_counts\": %s, \"owned_tiles\": %s, \"wrap\": %d, "
                        "\"representative_tile\": %d, \"economic_turn\": %d}",
                        static_cast<LPCSTR>(terrainJson), static_cast<LPCSTR>(ownedJson),
                        g_pGlobalMapState->hexNeighborWrapHorizontally20,
                        g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(
                            g_runtimeTestState.selectedNationSlot),
                        g_pSimMgr != 0 ? static_cast<int>(g_pSimMgr->economicTurn) : -1);
}

LONG WINAPI RuntimeTestUnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
  if (!g_runtimeTestState.finished && info != 0 && info->ExceptionRecord != 0) {
    TrapDebugger(kRuntimeDebugUnhandledException, "\"unhandled exception\"", info);
    CString fault;
    fault.Format("{\"code\": \"0x%08lx\", \"address\": \"%p\", \"phase\": \"%s\", "
                 "\"last_action\": \"%s\"}",
                 info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress,
                 PhaseName(), g_runtimeTestState.lastAction);
    AppendJsonArrayItem(g_faults, fault);
    g_runtimeTestState.finished = true;
    g_runtimeTestState.step = 0;
    g_runtimeTestState.phaseName = "finished";
    WriteResultFile("failed", "\"unhandled exception\"");
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

void InitializeDriver(RuntimeScenario& scenario, unsigned int seed) {
  g_runtimeTestState.scenario = &scenario;
  g_runtimeTestState.seed = seed;
  g_runtimeTestState.startMs = GetTickCount();
  g_runtimeTestState.phaseStartMs = g_runtimeTestState.startMs;
  SetUnhandledExceptionFilter(RuntimeTestUnhandledExceptionFilter);

  DWORD resultPathLength =
      GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_RESULT", g_runtimeTestState.resultPath,
                              sizeof(g_runtimeTestState.resultPath));
  if (resultPathLength == 0 || resultPathLength >= sizeof(g_runtimeTestState.resultPath)) {
    lstrcpyA(g_runtimeTestState.resultPath, "runtime-test-result.json");
  }

  DWORD heartbeatPathLength = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_HEARTBEAT",
                                                      g_runtimeTestState.heartbeatPath,
                                                      sizeof(g_runtimeTestState.heartbeatPath));
  if (heartbeatPathLength >= sizeof(g_runtimeTestState.heartbeatPath)) {
    g_runtimeTestState.heartbeatPath[0] = 0;
  }

  DWORD debugRecordPathLength = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_DEBUG_RECORD",
                                                        g_runtimeTestState.debugRecordPath,
                                                        sizeof(g_runtimeTestState.debugRecordPath));
  if (debugRecordPathLength >= sizeof(g_runtimeTestState.debugRecordPath)) {
    g_runtimeTestState.debugRecordPath[0] = 0;
  }

  if (scenario.RequiresFixture()) {
    DWORD fixtureLength =
        GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_FIXTURE", g_runtimeTestState.fixturePath,
                                sizeof(g_runtimeTestState.fixturePath));
    if (fixtureLength == 0 || fixtureLength >= sizeof(g_runtimeTestState.fixturePath)) {
      Finish("failed", "\"IMPERIALISM_RUNTIME_TEST_FIXTURE is not set for load_saved_game\"");
      return;
    }
  } else if (lstrcmpA(scenario.Name(), "unknown") == 0) {
    Finish("failed", "\"unknown compiled runtime test\"");
    return;
  }
  SetStep(RunWaitingForManagers, "waiting_for_managers", "wait_for_managers");
}

void RunWaitingForManagers() {
  if (!RequiredManagersAreInitialized()) {
    WaitForNextTickOrTimeout("\"manager initialization timed out\"");
    return;
  }
  if (!ActiveScenario().RequiresMainWindow()) {
    ActiveScenario().OnManagersReady();
    return;
  }
  if (GetMainViewHostFromActiveThread() == 0) {
    WaitForNextTickOrTimeout("\"main view host initialization timed out\"");
    return;
  }
  CWnd* mainWindow = AfxGetThread()->GetMainWnd();
  if (mainWindow == 0 || mainWindow->m_hWnd == 0) {
    WaitForNextTickOrTimeout("\"main window initialization timed out\"");
    return;
  }
  g_runtimeTestState.mainWindowHandle = mainWindow->m_hWnd;

  ActiveScenario().OnManagersReady();
}

bool AdvanceInitialNewspaperIfNeeded();

void RunWaitingForMainMenu() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not become active\"");
    return;
  }

  srand(g_runtimeTestState.seed);
  MainMenuDriver menu(mainView);
  if (!menu.StartRandomGame()) {
    Fail("\"main-menu random-game button or native host is missing\"");
    return;
  }
  SetStep(RunWaitingForRandomSetup, "waiting_for_random_setup", "click_main_menu_rand");
  RequestAnotherDriverTick();
}

void RunWaitingForRandomSetup() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random-map setup did not become active\"");
    return;
  }

  RandomSetupDriver setup(mainView);
  g_runtimeTestState.selectedNationSlot = setup.SelectedNationSlot();
  SetStep(RunSettingCountryName, "setting_country_name", "wait_for_event_0x05dd");
  RequestAnotherDriverTick();
}

void RunSettingCountryName() {
  TView* mainView = MainView();
  if (!IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    Fail("\"random-map setup disappeared before set_text\"");
    return;
  }
  RandomSetupDriver setup(mainView);
  if (!setup.SetCountryName("Testland")) {
    Fail("\"country-name control is missing\"");
    return;
  }
  SetStep(RunSelectingDifficulty, "selecting_difficulty", "set_text_coun");
  RequestAnotherDriverTick();
}

void RunSelectingDifficulty() {
  TView* mainView = MainView();
  const unsigned long expectedTag = IsEasyStyleTest() ? kControlTagDif1 : kControlTagDif2;
  RandomSetupDriver setup(mainView);
  if (!setup.SelectDifficulty(expectedTag, IsEasyStyleTest())) {
    Fail("\"requested difficulty control is missing\"");
    return;
  }
  SetStep(RunActivatingOkay, "activating_okay",
          IsEasyStyleTest() ? "click_diff_dif1" : "select_diff_dif2");
  RequestAnotherDriverTick();
}

void RunActivatingOkay() {
  TView* mainView = MainView();
  RandomSetupDriver setup(mainView);
  if (!setup.Accept(IsEasyStyleTest())) {
    Fail("\"okay control or requested input path is missing\"");
    return;
  }
  if (IsEasyStyleTest()) {
    SetStep(RunWaitingForEasyStrategicMap, "waiting_for_easy_strategic_map", "click_okay");
  } else {
    SetStep(RunWaitingForStrategicMap, "waiting_for_strategic_map", "activate_okay");
  }
  RequestAnotherDriverTick();
}

bool NationModesMatchSelectedNation() {
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    short expected = nationSlot == g_runtimeTestState.selectedNationSlot ? 1 : 2;
    if (g_pSimMgr->nationControlModes[nationSlot] != expected) {
      return false;
    }
  }
  return true;
}

bool AdvanceInitialNewspaperIfNeeded() {
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x2103) {
    return false;
  }
  TView* mainView = MainView();
  if (!IsViewKindOf(mainView, RUNTIME_CLASS(TNewspaperView))) {
    Fail("\"event 0x2103 did not construct the newspaper view\"");
    return true;
  }
  if (g_runtimeTestState.newspaperAdvanced) {
    WaitForNextTickOrTimeout("\"newspaper end action did not advance to the combined map\"");
    return true;
  }
  TControl* endControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagEnd));
  if (endControl == 0 || endControl->IsActionable() == 0) {
    Fail("\"newspaper end control is missing or disabled\"");
    return true;
  }
  g_runtimeTestState.newspaperAdvanced = true;
  RecordAction("activate_newspaper_end");
  endControl->HandleEvent(endControl->GetEventNumber(), endControl, 0);
  RequestAnotherDriverTick();
  return true;
}

void RunWaitingForEasyStrategicMap() {
  const int eventCode = g_pUiRuntimeContext->currentTurnEventCode;
  if (eventCode == 0x3b8) {
    Fail("\"Easy difficulty incorrectly entered capital-site selection\"");
    return;
  }
  if (eventCode == 0x5e4) {
    Fail("\"single-player Easy game incorrectly entered multiplayer synchronization\"");
    return;
  }
  if (AdvanceInitialNewspaperIfNeeded()) {
    return;
  }
  TView* mainView = MainView();
  if (eventCode != 0x7dd || !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    WaitForNextTickOrTimeout("\"Easy random game did not reach the combined strategic map\"");
    return;
  }
  if (!g_ModalViewStack.IsEmpty()) {
    RecordUnexpectedModal(static_cast<TView*>(g_ModalViewStack.GetHead()));
    Fail("\"Easy random game unexpectedly displayed a modal capital prompt\"");
    return;
  }
  if (g_pSimMgr->difficultyLevel != 1) {
    Fail("\"native Easy selection did not store difficulty level 1\"");
    return;
  }
  if (g_pSimMgr->multiplayerSessionRole != 0) {
    Fail("\"single-player Easy game has a multiplayer session role\"");
    return;
  }
  if (!NationModesMatchSelectedNation()) {
    Fail("\"nation control modes do not match the Easy setup selection\"");
    return;
  }
  ActiveScenario().OnEasyMapReady();
}

void RunWaitingForStrategicMap() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    WaitForNextTickOrTimeout("\"strategic map did not become active\"");
    return;
  }
  SetStep(RunVerifyingStrategicMap, "verifying_strategic_map", "observe_event_0x03b8");
  RequestAnotherDriverTick();
}

void RunVerifyingStrategicMap() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"strategic map did not remain active\"");
    return;
  }
  if (g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site prompt did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TDialogBehavior* behavior = modal->GetDialogBehavior();
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (behavior == 0 || behavior->defaultCommandCode != kControlTagOkay || okay == 0) {
    RecordUnexpectedModal(modal);
    Fail("\"unexpected modal while entering the strategic map\"");
    return;
  }
  RecordHandledModal("city_site_prompt");
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetStep(RunWaitingForModalDismissal, "waiting_for_modal_dismissal",
          "activate_city_site_prompt_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForModalDismissal() {
  if (!g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site prompt did not dismiss\"");
    return;
  }
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"strategic map did not remain active after the city-site prompt\"");
    return;
  }
  if (g_pGlobalMapState == 0) {
    Fail("\"strategic map has no global map state\"");
    return;
  }
  if (g_pSimMgr->activeNationSlot != g_runtimeTestState.selectedNationSlot) {
    Fail("\"active nation differs from setup selection\"");
    return;
  }
  if (!NationModesMatchSelectedNation()) {
    Fail("\"nation control modes do not match the setup selection\"");
    return;
  }
  if (g_pSimMgr->difficultyLevel != 2) {
    Fail("\"difficulty level is not Normal\"");
    return;
  }
  TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
  TView* cancel = mapView->ResolveControlByTag(kControlTagCanc);
  TView* query = mapView->ResolveControlByTag(kControlTagQuer);
  if (cancel == 0 || query == 0) {
    Fail("\"city-site toolbar button controls are missing\"");
    return;
  }
  if (mapView->miniMapViewC0 == 0) {
    Fail("\"strategic map did not create its mini-map view\"");
    return;
  }
  const char* holdPhase = getenv("IMPERIALISM_RUNTIME_TEST_HOLD");
  if (holdPhase != 0 && lstrcmpiA(holdPhase, "capital") != 0) {
    RedrawWindow(mapView->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    Finish("passed", "null");
    return;
  }
  SetStep(RunPrimingMapHover, "priming_map_hover", "prime_city_site_hover");
  RequestAnotherDriverTick();
}

void RunPrimingMapHover() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"strategic map has no city-site hover view\"");
    return;
  }

  mapDialog->RefreshControl();
  mapDialog->ForceRedraw();
  CPoint point(256, 224);
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&point, 0);
  short paintedTile = static_cast<short>(mapDialog->paintedHoverTileIndex6e);
  signed char markerIndex = g_pGlobalMapState->terrainStateTable[paintedTile].markerSlotIndex10;
  if (markerIndex == -1 || mapDialog->tileMarkers7c[markerIndex].flag == 0) {
    Fail("\"primed city-site hover tile is not present in the render cache\"");
    return;
  }
  SetStep(RunDispatchingMapHotkey, "dispatching_map_hotkey", "forward_map_hotkey_x");
  RequestAnotherDriverTick();
}

void RunDispatchingMapHotkey() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  if (mapView == 0) {
    Fail("\"strategic map has no map input view\"");
    return;
  }

  TKeyCommandEvent commandEvent;
  commandEvent.commandCode = 'x';
  commandEvent.keyFlags = 0;
  commandEvent.handledMarker = 0;
  mapView->DoKeyEvent(&commandEvent);

  TMapDialog* mapDialog = mapView->subview2A8;
  if (mapDialog == 0) {
    Fail("\"strategic map has no scrollable map dialog\"");
    return;
  }

  TCitySiteView* citySiteView = static_cast<TCitySiteView*>(mapDialog);
  if (g_wMapDialogViewportTileSpan != 9) {
    Fail("\"strategic-map viewport tile span was not initialized\"");
    return;
  }
  mapDialog->SetMapDialogCellCoordinatesAndRefresh(citySiteView->minColBound368 + 1,
                                                   citySiteView->minRowBound370 + 1, 0);
  for (int scroll = 0; scroll < 0x80; ++scroll) {
    mapView->Scroll(4);
  }
  int rightEdgeViewportX = mapDialog->viewportOrigin60.x;
  if (rightEdgeViewportX != citySiteView->maxColBound36c * 0x40) {
    Fail("\"right-edge scrolling stopped before the strategic map clamp\"");
    return;
  }
  mapView->Scroll(4);
  if (mapDialog->viewportOrigin60.x != rightEdgeViewportX) {
    Fail("\"right-edge scrolling moved beyond the strategic map clamp\"");
    return;
  }
  int viewportYBeforeTopEdgeScroll = mapDialog->viewportOrigin60.y;
  mapView->Scroll(2);
  if (mapDialog->viewportOrigin60.y <= viewportYBeforeTopEdgeScroll) {
    Fail("\"top-edge scrolling moved the strategic map viewport downward\"");
    return;
  }
  short finalTile = static_cast<short>(g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(
      g_runtimeTestState.selectedNationSlot));
  for (short tile = 0; tile < 0x1950; ++tile) {
    const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
    if (terrain.GetTerrainKind() == kStrategicTerrainMountain &&
        terrain.ownerNationTag04 == g_runtimeTestState.selectedNationSlot) {
      finalTile = tile;
      break;
    }
  }
  citySiteView->SetMapViewTileIndex(finalTile);
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(MainView(), RUNTIME_CLASS(TMapUberPicture))) {
    Fail("\"map hotkey forwarding left the strategic map\"");
    return;
  }
  SetStep(RunExercisingMapHover, "exercising_map_hover", "exercise_city_site_hover");
  RequestAnotherDriverTick();
}

void RunExercisingMapHover() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"strategic map has no city-site hover view\"");
    return;
  }

  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
  CPoint point(0, 0);
  mapDialog->HandleCursorHoverSelectionByChildHitTestAndFallback(&point, 0);
  SetGWorld(savedSurface, savedSurfaceFlags);
  mapView->RefreshControl();
  mapView->ForceRedraw();
  TView* cancel = mapView->ResolveControlByTag(kControlTagCanc);
  if (!RuntimeUiDriver::ClickView(cancel)) {
    Fail("\"strategic-map return button or native host is missing\"");
    return;
  }
  SetStep(RunReturningToRandomSetup, "returning_to_random_setup", "click_strategic_map_canc");
  RequestAnotherDriverTick();
}

void RunReturningToRandomSetup() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random setup did not return after leaving the strategic map\"");
    return;
  }

  TView* cancel = mainView->ResolveControlByTag(kControlTagCncl);
  if (!RuntimeUiDriver::ClickView(cancel)) {
    Fail("\"returned random setup main-menu button or native host is missing\"");
    return;
  }
  SetStep(RunReturningToMainMenu, "returning_to_main_menu", "click_returned_setup_cncl");
  RequestAnotherDriverTick();
}

void RunReturningToMainMenu() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dc ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TGameSetupPicture))) {
    WaitForNextTickOrTimeout("\"main menu did not return after leaving random setup\"");
    return;
  }

  TView* randomButton = mainView->ResolveControlByTag(kControlTagRand);
  if (!RuntimeUiDriver::ClickView(randomButton)) {
    Fail("\"returned main-menu random-game button or native host is missing\"");
    return;
  }
  SetStep(RunReenteringRandomSetup, "reentering_random_setup", "click_returned_main_menu_rand");
  RequestAnotherDriverTick();
}

void RunReenteringRandomSetup() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TSetupRandomMapPicture))) {
    WaitForNextTickOrTimeout("\"random setup did not reopen from the returned main menu\"");
    return;
  }

  TView* hard = mainView->ResolveControlByTag(kControlTagDif3);
  if (!RuntimeUiDriver::ClickView(hard)) {
    Fail("\"reopened random setup difficulty control or native host is missing\"");
    return;
  }
  SetStep(RunVerifyingReturnedRandomSetup, "verifying_returned_random_setup",
          "click_reopened_setup_dif3");
  RequestAnotherDriverTick();
}

void RunVerifyingReturnedRandomSetup() {
  TView* mainView = MainView();
  TRadioTextCluster* difficulty =
      mainView != 0
          ? static_cast<TRadioTextCluster*>(mainView->ResolveControlByTag(kControlTagDiff))
          : 0;
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x5dd || difficulty == 0 ||
      difficulty->selectedTag88 != static_cast<int>(kControlTagDif3)) {
    Fail("\"returned random setup did not accept the difficulty click\"");
    return;
  }

  TControl* okay = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagOkay));
  if (okay == 0) {
    Fail("\"reopened random setup okay control is missing\"");
    return;
  }
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetStep(RunWaitingForSecondCitySite, "waiting_for_second_city_site",
          "activate_reopened_setup_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForSecondCitySite() {
  TView* mainView = MainView();
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x3b8 ||
      !IsViewKindOf(mainView, RUNTIME_CLASS(TMapUberPicture)) || g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"second city-site selector or prompt did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (okay == 0) {
    RecordUnexpectedModal(modal);
    Fail("\"second city-site prompt has no okay control\"");
    return;
  }
  RecordHandledModal("city_site_prompt");
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  SetStep(RunWaitingForSecondPromptDismissal, "waiting_for_second_prompt_dismissal",
          "activate_second_city_site_prompt_okay");
  RequestAnotherDriverTick();
}

void RunWaitingForSecondPromptDismissal() {
  if (!g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"second city-site prompt did not dismiss\"");
    return;
  }

  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || !IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"second city-site selector has no TCitySiteView\"");
    return;
  }

  short citySite = -1;
  for (short tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    const TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    StrategicTerrainKind terrainKind = tile.GetTerrainKind();
    bool supportsCity =
        terrainKind == kStrategicTerrainPlains || terrainKind == kStrategicTerrainFarmland ||
        terrainKind == kStrategicTerrainForest || terrainKind == kStrategicTerrainDesert;
    if (supportsCity && tile.ownerNationTag04 == g_runtimeTestState.selectedNationSlot &&
        tile.recruitSearchVisited0e == 0) {
      citySite = tileIndex;
      break;
    }
  }
  if (citySite == -1) {
    Fail("\"random map has no valid city-site candidate for the selected nation\"");
    return;
  }

  SetStep(RunWaitingForCitySiteConfirmation, "waiting_for_city_site_confirmation",
          "submit_valid_city_site");
  static_cast<TCitySiteView*>(mapDialog)->HandleMapClickByInteractionMode(citySite, 0);
  RequestAnotherDriverTick();
}

void RunWaitingForCitySiteConfirmation() {
  if (g_ModalViewStack.IsEmpty()) {
    WaitForNextTickOrTimeout("\"city-site confirmation did not become active\"");
    return;
  }

  TWindow* modal = static_cast<TWindow*>(g_ModalViewStack.GetHead());
  TView* dialog = modal->ResolveControlByTag(kControlTagDialog);
  TControl* okay = static_cast<TControl*>(modal->ResolveControlByTag(kControlTagOkay));
  if (dialog == 0 || okay == 0) {
    Fail("\"city-site confirmation tree is incomplete\"");
    return;
  }
  if (modal->IsActionable() == 0 || dialog->IsActionable() == 0 || okay->IsActionable() == 0 ||
      dialog->ownerContext != modal || okay->ownerContext != dialog || modal->nativeWindow50 == 0 ||
      dialog->nativeWindow50 != modal->nativeWindow50 ||
      okay->nativeWindow50 != modal->nativeWindow50) {
    Fail("\"city-site confirmation tree is not attached to its active native host\"");
    return;
  }
  g_capitalConfirmationUiSnapshot = CaptureUiSnapshot(0x3b9, modal);
  if (g_pActiveQuickDrawSurfaceContextHead != &g_defaultQuickDrawSurfaceSentinel ||
      g_pQuickDrawMemoryDc != 0) {
    Fail("\"city-site confirmation inherited the strategic map QuickDraw surface\"");
    return;
  }
  RedrawWindow(modal->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
  const char* holdPhase = getenv("IMPERIALISM_RUNTIME_TEST_HOLD");
  if (holdPhase != 0 && lstrcmpiA(holdPhase, "capital") == 0) {
    Finish("passed", "null");
    return;
  }
  RecordHandledModal("city_site_confirmation");
  SetStep(RunWaitingForCombinedMap, "waiting_for_combined_map", "accept_city_site_confirmation");
  okay->HandleEvent(okay->GetEventNumber(), okay, 0);
  RequestAnotherDriverTick();
}

void RunWaitingForCombinedMap() {
  if (AdvanceInitialNewspaperIfNeeded()) {
    return;
  }
  WaitForNextTickOrTimeout("\"accepted city site did not advance to the combined map\"");
}

void RunVerifyingCombinedMapExtents() {
  TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
  if (mapDialog == 0 || IsViewKindOf(mapDialog, RUNTIME_CLASS(TCitySiteView))) {
    Fail("\"combined map retained the country-bounded city-site view\"");
    return;
  }
  g_MapInteractionPreviewPoint_006a3370 = CPoint(0, 0);
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == 0) {
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(0x6b, 0, 0);
    mapView->Scroll(4);
    if (mapDialog->viewportOrigin60.x != 0) {
      Fail("\"combined-map right-edge scrolling did not wrap to the left edge\"");
      return;
    }
    mapView->Scroll(8);
    if (mapDialog->viewportOrigin60.x != 0x6b * 0x40) {
      Fail("\"combined-map left-edge scrolling did not wrap to the right edge\"");
      return;
    }
  } else {
    int rightColumn = 0x6e - g_wMapDialogViewportTileSpan;
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(0x7fff, 0, 0);
    if (mapDialog->viewportOrigin60.x != rightColumn * 0x40) {
      Fail("\"combined-map scrolling stopped before the full right edge\"");
      return;
    }
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(-0x7fff, 0, 0);
    if (mapDialog->viewportOrigin60.x != 0x40) {
      Fail("\"combined-map scrolling stopped before the full left edge\"");
      return;
    }
  }

  mapDialog->SetMapDialogCellCoordinatesAndRefresh(1, 0x7fff, 0);
  if (mapDialog->viewportOrigin60.y != 0x35 * 0x40) {
    Fail("\"combined-map scrolling stopped before the full bottom edge\"");
    return;
  }
  mapDialog->SetMapDialogCellCoordinatesAndRefresh(1, -0x7fff, 0);
  if (mapDialog->viewportOrigin60.y != 0) {
    Fail("\"combined-map scrolling stopped before the full top edge\"");
    return;
  }
  ActiveScenario().OnCombinedMapReady();
}

void RunScenarioOwnedStep() {
  ActiveScenario().RunScenarioStep();
}

} // namespace

void RuntimeScenario::Start(RuntimeContext& context) {
  InitializeDriver(*this, context.Seed());
}

void RuntimeScenario::Tick(RuntimeContext&) {
  if (g_runtimeTestState.finished) {
    if (HoldRequested()) {
      MaybeWriteHeartbeat();
      RequestAnotherDriverTick();
    }
    return;
  }

  ++g_runtimeTestState.idleTicks;
  ++g_runtimeTestState.phaseTicks;
  MaybeWriteHeartbeat();
  char forcedFailure[2];
  if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_FORCE_FAILURE", forcedFailure,
                              sizeof(forcedFailure)) != 0) {
    Fail("\"forced runtime debugger failure\"");
    return;
  }
  if (SpinRequestedForCurrentPhase()) {
    RequestAnotherDriverTick();
    return;
  }
  if (g_runtimeTestState.step == 0) {
    Fail("\"runtime-test driver entered an invalid phase\"");
    return;
  }
  g_runtimeTestState.step();
}

void RuntimeScenario::Pulse(RuntimeContext&) {
  MaybeWriteHeartbeat();
}

void RuntimeScenario::ObserveBuiltUiTree(RuntimeContext&, int eventCode, TView* root) {
  if (!IsRandomGameTest()) {
    return;
  }
  if (eventCode == 0x5dd) {
    g_randomSetupUiSnapshot = CaptureUiSnapshot(eventCode, root);
  } else if (eventCode == 0x3b8 || (IsEasyStyleTest() && eventCode == 0x7dd)) {
    // Capture only the first arrival: later 0x7dd trees (turn-advance cycles)
    // legitimately diverge from the factory expectation as the game evolves.
    if (g_strategicMapUiSnapshot.IsEmpty()) {
      g_strategicMapUiSnapshot = CaptureUiSnapshot(eventCode, root);
    }
  }
  ObserveScenarioUiTree(eventCode, root);
}

void RuntimeScenario::ObserveTurnEvent(RuntimeContext&, int eventCode) {
  if (RecordsGameFlow()) {
    CString event;
    event.Format("%s\"0x%04x\"", g_activatedEventSequence.GetLength() == 1 ? "" : ", ",
                 static_cast<unsigned short>(eventCode));
    g_activatedEventSequence += event;
  }
  if (RecordsGameFlow() && g_pSimMgr != 0 && g_pSimMgr->multiplayerSessionRole == 0 &&
      eventCode == 0x5e4) {
    Fail("\"single-player game entered multiplayer synchronization event 0x5e4\"");
    return;
  }
  if (IsEasyStyleTest() && eventCode == 0x3b8) {
    Fail("\"Easy difficulty entered capital-site selection event 0x3b8\"");
    return;
  }
  if (g_runtimeTestState.step != RunWaitingForCitySiteConfirmation &&
      g_runtimeTestState.step != RunWaitingForCombinedMap) {
    return;
  }
  if (eventCode != 0x7dd) {
    return;
  }
  SetStep(RunVerifyingCombinedMapExtents, "verifying_combined_map_extents", "observe_event_0x07dd");
  RunVerifyingCombinedMapExtents();
}

unsigned int RuntimeScenario::RandomSeed(RuntimeContext& context) {
  return context.Seed();
}

void RuntimeScenario::FailHarness(RuntimeContext&, const char* failure) {
  Fail(failure);
}

bool RuntimeScenario::RequiresMainWindow() const {
  return true;
}

bool RuntimeScenario::RequiresFixture() const {
  return false;
}

bool RuntimeScenario::UsesRandomGameFlow() const {
  return false;
}

bool RuntimeScenario::UsesEasyDifficulty() const {
  return false;
}

bool RuntimeScenario::RecordsGameFlow() const {
  return false;
}

bool RuntimeScenario::RequiresCityUiSnapshot() const {
  return false;
}

void RuntimeScenario::OnManagersReady() {
  StartRandomGameFlow();
}

void RuntimeScenario::OnEasyMapReady() {
  Pass();
}

void RuntimeScenario::OnCombinedMapReady() {
  Pass();
}

void RuntimeScenario::RunScenarioStep() {
  FailScenario("\"scenario entered an unimplemented owned phase\"");
}

void RuntimeScenario::ObserveScenarioUiTree(int, TView*) {}

void RuntimeScenario::Pass() {
  Finish("passed", "null");
}

void RuntimeScenario::FailScenario(const char* failure) {
  Fail(failure);
}

bool RuntimeScenario::WaitForScenarioTick(const char* failure) {
  return WaitForNextTickOrTimeout(failure);
}

void RuntimeScenario::RequestScenarioTick() {
  RequestAnotherDriverTick();
}

void RuntimeScenario::EnterScenarioStep(const char* phaseName, const char* action) {
  SetStep(RunScenarioOwnedStep, phaseName, action);
}

void RuntimeScenario::StartRandomGameFlow() {
  g_pGlobalUiRootController->PostTurnEventCodeMessage2420(0x5dc);
  SetStep(RunWaitingForMainMenu, "waiting_for_main_menu", "post_turn_event_0x05dc");
  RequestAnotherDriverTick();
}

TView* RuntimeScenario::CurrentMainView() const {
  return MainView();
}

unsigned long RuntimeScenario::ScenarioPhaseTicks() const {
  return g_runtimeTestState.phaseTicks;
}

unsigned long RuntimeScenario::ScenarioPhaseElapsedMs() const {
  return GetTickCount() - g_runtimeTestState.phaseStartMs;
}

const char* RuntimeScenario::FixturePath() const {
  return g_runtimeTestState.fixturePath;
}

void RuntimeScenario::SetSelectedNation(short nationSlot) {
  g_runtimeTestState.selectedNationSlot = nationSlot;
}

bool RuntimeScenario::AdvanceNewspaperIfNeeded() {
  return AdvanceInitialNewspaperIfNeeded();
}

void RuntimeScenario::ResetNewspaperAdvance() {
  g_runtimeTestState.newspaperAdvanced = false;
}

void RuntimeScenario::RecordUnexpectedModalView(TView* modal) {
  RecordUnexpectedModal(modal);
}

bool RuntimeScenario::HasCityUiSnapshot() const {
  return !g_cityUiSnapshot.IsEmpty();
}

void RuntimeScenario::CaptureCityUiSnapshot(int eventCode, TView* root) {
  g_cityUiSnapshot = CaptureUiSnapshot(eventCode, root);
}

void RuntimeTestObserveBuiltUiTree(int eventCode, TView* root) {
  RuntimeHarness::ObserveBuiltUiTree(eventCode, root);
}
