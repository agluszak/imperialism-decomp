#include "RuntimeScenario.h"

#include "RuntimeGameStateCapture.h"

#include "RuntimeContext.h"
#include "RuntimeExceptionCapture.h"
#include "RuntimeHarness.h"
#include "RuntimeHeartbeat.h"
#include "RuntimeObservations.h"
#include "RuntimeResultWriter.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"
#include "RuntimeUiDriver.h"
#include "flows/RuntimeFlow.h"

#include "game/ImperialismApp.h"
#include "game/core/global_data_tables.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/CIncludeView.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TGameSetupPicture.h"
#include "game/ui_screens/TNewspaperView.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

#include <windows.h>

namespace {

bool RequiredManagersAreInitialized() {
  return g_pAmbitApplication != 0 && g_pSimMgr != 0 && g_pViewMgr != 0 && g_pDisplayMgr != 0 &&
         g_pAssetMgr != 0;
}

void RequestGameClose(HWND mainWindow) {
  if (mainWindow != 0) {
    PostMessageA(mainWindow, WM_CLOSE, 0, 0);
  } else {
    PostQuitMessage(0);
  }
}

} // namespace

RuntimeScenario::RuntimeScenario()
    : run(0), activeFlow(0), driverState(kWaitingForManagers),
      awaitedObservations(kObserveApplicationIdle), advancing(false) {}

void RuntimeScenario::Start(RuntimeContext& context) {
  run = &context.Run();
  activeFlow = 0;
  driverState = kWaitingForManagers;
  awaitedObservations = kObserveApplicationIdle;
  advancing = false;
  run->StartScenario(this);
  RuntimeExceptionCapture::Install(*run, *this);

  if (RequiresFixture() && !run->HasFixturePath()) {
    FailScenario("IMPERIALISM_RUNTIME_TEST_FIXTURE is not set for load_saved_game");
    return;
  }
  run->EnterPhase("waiting_for_managers", "wait_for_managers");
  AwaitAt(kObserveApplicationIdle, "the game to finish initializing its managers", 0, 0);
}

void RuntimeScenario::Observe(RuntimeContext&, unsigned int observationKinds) {
  if (run->IsFinished()) {
    if (run->HoldRequested()) {
      WriteRuntimeHeartbeat(*run);
    }
    return;
  }

  WriteRuntimeHeartbeat(*run);
  char forcedFailure[2];
  if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_FORCE_FAILURE", forcedFailure,
                              sizeof(forcedFailure)) != 0) {
    FailScenario("forced runtime debugger failure");
    return;
  }
  if (run->SpinRequestedForCurrentPhase()) {
    AwaitAt(kObserveApplicationIdle, "IMPERIALISM_RUNTIME_TEST_SPIN to release this phase", 0, 0);
    return;
  }

  if ((awaitedObservations & observationKinds) == 0) {
    return;
  }
  AdvanceDriver(observationKinds);
}

void RuntimeScenario::AdvanceDriver(unsigned int observationKinds) {
  (void)observationKinds;
  if (advancing || run->IsFinished()) {
    return;
  }
  advancing = true;
  // The previous wait has been satisfied; whatever runs below re-arms, or terminates.
  awaitedObservations = kObserveNone;
  run->AwaitState().Clear();
  if (driverState == kWaitingForManagers) {
    AdvanceWaitingForManagers();
  } else if (driverState == kRunningScenario) {
    AdvanceScenario();
  } else if (activeFlow == 0) {
    FailScenario("runtime scenario has no active navigation flow");
  } else {
    RuntimeFlowStatus status = activeFlow->Advance(*this);
    if (status == kRuntimeFlowCheckpoint) {
      OnFlowCheckpoint(activeFlow->Checkpoint());
    } else if (status == kRuntimeFlowComplete && !run->IsFinished()) {
      FailScenario("navigation flow completed without handing control to the scenario");
    }
  }
  advancing = false;
}

void RuntimeScenario::AdvanceWaitingForManagers() {
  if (!RequiredManagersAreInitialized()) {
    Await(kObserveApplicationIdle, "manager initialization has not completed");
    return;
  }
  if (RequiresMainWindow()) {
    if (GetMainViewHostFromActiveThread() == 0) {
      Await(kObserveApplicationIdle, "main view host initialization has not completed");
      return;
    }
    CWnd* mainWindow = AfxGetThread()->GetMainWnd();
    if (mainWindow == 0 || mainWindow->m_hWnd == 0) {
      Await(kObserveApplicationIdle, "main window initialization has not completed");
      return;
    }
    run->SetMainWindowHandle(mainWindow->m_hWnd);
  }
  OnManagersReady();
}

void RuntimeScenario::Pulse(RuntimeContext&) {
  WriteRuntimeHeartbeat(*run);
}

void RuntimeScenario::ObserveBuiltUiTree(RuntimeContext&, int eventCode, TView* root) {
  if (run->RequestsCapture(kRuntimeCaptureUiTree)) {
    if (eventCode == 0x5dd) {
      run->SetRandomSetupUiSnapshot(CaptureRuntimeUiSnapshot(eventCode, root));
    } else if (eventCode == 0x3b8 || (DifficultyLevel() <= 1 && eventCode == 0x7dd)) {
      if (!run->HasStrategicMapUiSnapshot()) {
        run->SetStrategicMapUiSnapshot(CaptureRuntimeUiSnapshot(eventCode, root));
      }
    }
  }
  ObserveScenarioUiTree(eventCode, root);
}

void RuntimeScenario::ObserveTurnEvent(RuntimeContext&, int eventCode) {
  if (RecordsGameFlow() && g_pSimMgr != 0 && g_pSimMgr->multiplayerSessionRole == 0 &&
      eventCode == 0x5e4) {
    FailScenario("single-player game entered multiplayer synchronization event 0x5e4");
    return;
  }
  if (DifficultyLevel() <= 1 && eventCode == 0x3b8) {
    FailScenario("difficulty that skips capital selection entered event 0x3b8");
    return;
  }
  if (driverState == kRunningFlow && activeFlow != 0) {
    activeFlow->ObserveTurnEvent(*this, eventCode);
  }
}

unsigned int RuntimeScenario::RandomSeed(RuntimeContext& context) {
  return context.Seed();
}

void RuntimeScenario::FailHarness(RuntimeContext&, const char* failure) {
  FailScenario(failure);
}

bool RuntimeScenario::RequiresMainWindow() const {
  return true;
}

bool RuntimeScenario::RequiresFixture() const {
  return false;
}

int RuntimeScenario::DifficultyLevel() const {
  return 2;
}

const char* RuntimeScenario::RandomSetupPlanetSeed() const {
  return 0;
}

bool RuntimeScenario::RecordsGameFlow() const {
  // Catalog policy (RuntimeTestSpec.record_game_flow), not a per-scenario override.
  return run != 0 && run->RecordsGameFlow();
}

bool RuntimeScenario::RequiresScenarioUiSnapshot() const {
  // Declaring any snapshot event in the catalog is what asks for the capture.
  return run != 0 && run->CapturesAnyUiTree();
}

bool RuntimeScenario::BeforeInitialNewspaperExit() {
  return true;
}

RuntimeFlow* RuntimeScenario::NavigationFlow() {
  return 0;
}

void RuntimeScenario::OnManagersReady() {
  activeFlow = NavigationFlow();
  if (activeFlow == 0) {
    FailScenario("scenario did not provide a navigation flow");
    return;
  }
  driverState = kRunningFlow;
  activeFlow->Start(*this);
}

void RuntimeScenario::OnFlowCheckpoint(RuntimeFlowCheckpoint checkpoint) {
  if (checkpoint == kRuntimeCapitalSelectionReady) {
    activeFlow->ContinueFromCheckpoint();
    ContinueAfterAction();
    return;
  }
  driverState = kRunningScenario;
  if (checkpoint == kRuntimeMapReadyWithoutCapitalSelection) {
    OnMapReadyWithoutCapitalSelection();
  } else if (checkpoint == kRuntimeCombinedMapReady || checkpoint == kRuntimeLoadedMapReady) {
    OnCombinedMapReady();
  } else {
    FailScenario("navigation flow reported an unknown checkpoint");
  }
}

void RuntimeScenario::OnMapReadyWithoutCapitalSelection() {
  Pass();
}

void RuntimeScenario::OnCombinedMapReady() {
  Pass();
}

void RuntimeScenario::AdvanceScenario() {
  FailScenario("scenario entered an unimplemented owned phase");
}

void RuntimeScenario::ObserveScenarioUiTree(int eventCode, TView* root) {
  // The catalog names the events worth capturing; every scenario that overrode this was
  // writing the same `if (eventCode == kTurnEventX) CaptureScenarioUiSnapshot(...)` by hand.
  if (run != 0 && run->CapturesUiTreeAt(eventCode)) {
    CaptureScenarioUiSnapshot(eventCode, root);
  }
}

void RuntimeScenario::Finish(const char* status) {
  run->Finish();
  if (RecordsGameFlow() && lstrcmpA(status, "passed") == 0) {
    CaptureRuntimeMapState(*run);
  }
  if (lstrcmpA(status, "passed") == 0) {
    CaptureRuntimeGameState(*run);
  }
  if (!WriteRuntimeResult(*run, status)) {
    OutputDebugStringA("Imperialism runtime test could not write its result file.\n");
  }
  if (!run->HoldRequested()) {
    RequestGameClose(run->MainWindowHandle());
  }
}

void RuntimeScenario::Pass() {
  Finish("passed");
}

void RuntimeScenario::FailScenario(const char* failure) {
  run->RecordAssertion(run->PhaseName(), failure, true);
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, failure, 0);
  Finish("failed");
}

void RuntimeScenario::FailScenarioText(const char* failure) {
  FailScenario(failure != 0 ? failure : "");
}

void RuntimeScenario::FailScenarioTextAs(const char* assertionId, const char* failure) {
  const char* message = failure != 0 ? failure : "";
  run->RecordAssertion(assertionId, message, true);
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, message, 0);
  Finish("failed");
}

bool RuntimeScenario::Require(const char* assertionId, bool condition, const char* failure) {
  if (condition) {
    return true;
  }
  run->RecordAssertion(assertionId, failure, true);
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, failure, 0);
  Finish("failed");
  return false;
}

bool RuntimeScenario::Check(const char* assertionId, bool condition, const char* failure) {
  if (!condition) {
    run->RecordAssertion(assertionId, failure, false);
  }
  return condition;
}

bool RuntimeScenario::FinishChecks() {
  if (!run->HasAssertionFailures()) {
    return false;
  }
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, run->FirstFailure(), 0);
  Finish("failed");
  return true;
}

void RuntimeScenario::AwaitUiChange(const char* description) {
  Await(kObserveUiStateChanged, description);
}

void RuntimeScenario::Await(unsigned int observationKinds, const char* description) {
  AwaitAt(observationKinds, description, 0, 0);
}

void RuntimeScenario::AwaitAt(unsigned int observationKinds, const char* expression,
                              const char* file, int line) {
  awaitedObservations = observationKinds;
  run->AwaitState().Arm(observationKinds, expression, file, line);
}

void RuntimeScenario::ContinueAfterAction() {
  // Named so a stall immediately after an action reports the action rather than an empty
  // wait; run->LastAction() says which action it was.
  AwaitAt(kObserveApplicationIdle, "the application to go idle after the last action", 0, 0);
}

void RuntimeScenario::EnterScenarioStep(const char* phaseName, const char* action) {
  driverState = kRunningScenario;
  run->EnterPhase(phaseName, action);
  run->ResetHeartbeat();
  WriteRuntimeHeartbeat(*run);
}

void RuntimeScenario::EnterFlowPhase(const char* phaseName, const char* action) {
  driverState = kRunningFlow;
  run->EnterPhase(phaseName, action);
}

void RuntimeScenario::RecordSerializationRoundtripReport(JSON_Value* report) {
  run->SetCapture("serialization_roundtrip", report);
}

TView* RuntimeScenario::CurrentMainView() const {
  return RuntimeMainView();
}

const char* RuntimeScenario::FixturePath() const {
  return run->FixturePath();
}

void RuntimeScenario::SetSelectedNation(short nationSlot) {
  run->SetSelectedNationSlot(nationSlot);
}

bool RuntimeScenario::AdvanceNewspaperIfNeeded() {
  if (g_pViewMgr->currentTurnEventCode != 0x2103) {
    return false;
  }
  TView* mainView = RuntimeMainView();
  if (!RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TNewspaperView))) {
    AwaitUiChange("event 0x2103 has not constructed the newspaper view yet");
    return true;
  }
  if (run->NewspaperAdvanced()) {
    AwaitUiChange("newspaper end action did not advance to the combined map");
    return true;
  }
  if (!BeforeInitialNewspaperExit()) {
    return true;
  }
  RuntimeControlSelector endSelector(kControlTagEnd, RUNTIME_CLASS(TControl));
  if (RuntimeUiDriver::RequireControl(mainView, endSelector, 0) == 0) {
    Await(kObservePaintCompleted | kObserveInvalidationRequested | kObserveGameStateChanged,
          "newspaper controls are not actionable yet");
    return true;
  }
  CString failure;
  if (!RuntimeUiDriver::Activate(mainView, endSelector, &failure)) {
    FailScenario(static_cast<LPCSTR>(failure));
    return true;
  }
  run->SetNewspaperAdvanced(true);
  ContinueAfterAction();
  return true;
}

void RuntimeScenario::ResetNewspaperAdvance() {
  run->SetNewspaperAdvanced(false);
}

bool RuntimeScenario::HasScenarioUiSnapshot() const {
  return run->HasScenarioUiSnapshot();
}

void RuntimeScenario::CaptureScenarioUiSnapshot(int eventCode, TView* root) {
  run->SetScenarioUiSnapshot(CaptureRuntimeUiSnapshot(eventCode, root));
}

void RuntimeScenario::CaptureCurrentScreenSnapshot() {
  CaptureScenarioUiSnapshot(g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1,
                            RuntimeMainView());
}

bool RuntimeScenario::HoldAtScenarioScreen(const char* screenName) const {
  return run->HoldAt(screenName);
}

RuntimeRun& RuntimeScenario::RunState() const {
  return *run;
}

void RuntimeTestObserveBuiltUiTree(int eventCode, TView* root) {
  RuntimeHarness::ObserveBuiltUiTree(eventCode, root);
}
