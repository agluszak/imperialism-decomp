#include "RuntimeScenario.h"

#include "RuntimeContext.h"
#include "RuntimeExceptionCapture.h"
#include "RuntimeHarness.h"
#include "RuntimeHeartbeat.h"
#include "RuntimeJson.h"
#include "RuntimeObservations.h"
#include "RuntimeResultWriter.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"
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
  return g_pGlobalUiRootController != 0 && g_pSimMgr != 0 && g_pUiRuntimeContext != 0 &&
         g_pDisplayMgr != 0 && g_pUiViewManager != 0;
}

void RequestAnotherDriverTick() {
  PostThreadMessageA(GetCurrentThreadId(), WM_NULL, 0, 0);
}

void RequestGameClose(HWND mainWindow) {
  if (mainWindow != 0) {
    PostMessageA(mainWindow, WM_CLOSE, 0, 0);
  } else {
    PostQuitMessage(0);
  }
}

void FourCcText(unsigned int tag, char text[5]) {
  text[0] = static_cast<char>(tag >> 24);
  text[1] = static_cast<char>(tag >> 16);
  text[2] = static_cast<char>(tag >> 8);
  text[3] = static_cast<char>(tag);
  text[4] = 0;
}

} // namespace

RuntimeScenario::RuntimeScenario() : run(0), activeFlow(0), driverState(kWaitingForManagers) {}

void RuntimeScenario::Start(RuntimeContext& context) {
  run = &context.Run();
  activeFlow = 0;
  driverState = kWaitingForManagers;
  run->StartScenario(this);
  RuntimeExceptionCapture::Install(*run, *this);

  if (RequiresFixture() && !run->HasFixturePath()) {
    Finish("failed", "\"IMPERIALISM_RUNTIME_TEST_FIXTURE is not set for load_saved_game\"");
    return;
  }
  run->EnterPhase("waiting_for_managers", "wait_for_managers");
}

void RuntimeScenario::Tick(RuntimeContext&) {
  if (run->IsFinished()) {
    if (run->HoldRequested()) {
      WriteRuntimeHeartbeat(*run);
      RequestAnotherDriverTick();
    }
    return;
  }

  run->CountTick();
  WriteRuntimeHeartbeat(*run);
  char forcedFailure[2];
  if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_FORCE_FAILURE", forcedFailure,
                              sizeof(forcedFailure)) != 0) {
    FailScenario("\"forced runtime debugger failure\"");
    return;
  }
  if (run->SpinRequestedForCurrentPhase()) {
    RequestAnotherDriverTick();
    return;
  }

  if (driverState == kWaitingForManagers) {
    TickWaitingForManagers();
    return;
  }
  if (driverState == kRunningScenario) {
    TickScenario();
    return;
  }
  if (activeFlow == 0) {
    FailScenario("\"runtime scenario has no active navigation flow\"");
    return;
  }

  RuntimeFlowStatus status = activeFlow->Tick(*this);
  if (status == kRuntimeFlowCheckpoint) {
    OnFlowCheckpoint(activeFlow->Checkpoint());
  } else if (status == kRuntimeFlowComplete && !run->IsFinished()) {
    FailScenario("\"navigation flow completed without handing control to the scenario\"");
  }
}

void RuntimeScenario::TickWaitingForManagers() {
  if (!RequiredManagersAreInitialized()) {
    WaitForScenarioTick("\"manager initialization timed out\"");
    return;
  }
  if (RequiresMainWindow()) {
    if (GetMainViewHostFromActiveThread() == 0) {
      WaitForScenarioTick("\"main view host initialization timed out\"");
      return;
    }
    CWnd* mainWindow = AfxGetThread()->GetMainWnd();
    if (mainWindow == 0 || mainWindow->m_hWnd == 0) {
      WaitForScenarioTick("\"main window initialization timed out\"");
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
  if (!run->CapturesSnapshot(kRuntimeSnapshotUi)) {
    return;
  }
  if (eventCode == 0x5dd) {
    run->RandomSetupUiSnapshot() = CaptureRuntimeUiSnapshot(eventCode, root);
  } else if (eventCode == 0x3b8 || (DifficultyLevel() <= 1 && eventCode == 0x7dd)) {
    if (run->StrategicMapUiSnapshot().IsEmpty()) {
      run->StrategicMapUiSnapshot() = CaptureRuntimeUiSnapshot(eventCode, root);
    }
  }
  ObserveScenarioUiTree(eventCode, root);
}

void RuntimeScenario::ObserveTurnEvent(RuntimeContext&, int eventCode) {
  if (RecordsGameFlow()) {
    CString event;
    event.Format("%s\"0x%04x\"", run->ActivatedEventSequence().GetLength() == 1 ? "" : ", ",
                 static_cast<unsigned short>(eventCode));
    run->ActivatedEventSequence() += event;
  }
  if (RecordsGameFlow() && g_pSimMgr != 0 && g_pSimMgr->multiplayerSessionRole == 0 &&
      eventCode == 0x5e4) {
    FailScenario("\"single-player game entered multiplayer synchronization event 0x5e4\"");
    return;
  }
  if (DifficultyLevel() <= 1 && eventCode == 0x3b8) {
    FailScenario("\"difficulty that skips capital selection entered event 0x3b8\"");
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

bool RuntimeScenario::RecordsGameFlow() const {
  return false;
}

bool RuntimeScenario::RequiresScenarioUiSnapshot() const {
  return false;
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
    FailScenario("\"scenario did not provide a navigation flow\"");
    return;
  }
  driverState = kRunningFlow;
  activeFlow->Start(*this);
}

void RuntimeScenario::OnFlowCheckpoint(RuntimeFlowCheckpoint checkpoint) {
  if (checkpoint == kRuntimeCapitalSelectionReady) {
    activeFlow->ContinueFromCheckpoint();
    RequestScenarioTick();
    return;
  }
  driverState = kRunningScenario;
  if (checkpoint == kRuntimeMapReadyWithoutCapitalSelection) {
    OnMapReadyWithoutCapitalSelection();
  } else if (checkpoint == kRuntimeCombinedMapReady || checkpoint == kRuntimeLoadedMapReady) {
    OnCombinedMapReady();
  } else {
    FailScenario("\"navigation flow reported an unknown checkpoint\"");
  }
}

void RuntimeScenario::OnMapReadyWithoutCapitalSelection() {
  Pass();
}

void RuntimeScenario::OnCombinedMapReady() {
  Pass();
}

void RuntimeScenario::TickScenario() {
  FailScenario("\"scenario entered an unimplemented owned phase\"");
}

void RuntimeScenario::ObserveScenarioUiTree(int, TView*) {}

void RuntimeScenario::Finish(const char* status, const char* failure) {
  run->Finish();
  if (RecordsGameFlow() && lstrcmpA(status, "passed") == 0) {
    CaptureRuntimeMapState(*run);
  }
  if (!WriteRuntimeResult(*run, *this, status, failure)) {
    OutputDebugStringA("Imperialism runtime test could not write its result file.\n");
  }
  if (!run->HoldRequested()) {
    RequestGameClose(run->MainWindowHandle());
  }
}

void RuntimeScenario::Pass() {
  Finish("passed", "null");
}

void RuntimeScenario::FailScenario(const char* failure) {
  run->RecordAssertion(run->PhaseName(), failure, true);
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, failure, 0);
  Finish("failed", failure);
}

bool RuntimeScenario::Require(const char* assertionId, bool condition, const char* failure) {
  if (condition) {
    return true;
  }
  run->RecordAssertion(assertionId, failure, true);
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, failure, 0);
  Finish("failed", failure);
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
  RuntimeExceptionCapture::Trap(*run, *this, kRuntimeDebugSemanticFailure, run->FirstFailureJson(),
                                0);
  Finish("failed", run->FirstFailureJson());
  return true;
}

bool RuntimeScenario::WaitForScenarioTick(const char* failure) {
  if (run->PhaseElapsedMs() >= run->PhaseTimeoutMs()) {
    FailScenario(failure);
    return false;
  }
  RequestAnotherDriverTick();
  return true;
}

void RuntimeScenario::RequestScenarioTick() {
  RequestAnotherDriverTick();
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

void RuntimeScenario::RecordSerializationRoundtripReport(const CString& reportJson) {
  run->SerializationRoundtripJson() = reportJson;
}

void RuntimeScenario::RecordHandledModal(const char* label) {
  CString entry;
  entry.Format("\"%s\"", label);
  RuntimeJson::AppendArrayItem(run->HandledModals(), entry);
}

TView* RuntimeScenario::CurrentMainView() const {
  return RuntimeMainView();
}

unsigned long RuntimeScenario::ScenarioPhaseTicks() const {
  return run->PhaseTicks();
}

unsigned long RuntimeScenario::ScenarioPhaseElapsedMs() const {
  return run->PhaseElapsedMs();
}

const char* RuntimeScenario::FixturePath() const {
  return run->FixturePath();
}

void RuntimeScenario::SetSelectedNation(short nationSlot) {
  run->SetSelectedNationSlot(nationSlot);
}

bool RuntimeScenario::AdvanceNewspaperIfNeeded() {
  if (g_pUiRuntimeContext->currentTurnEventCode != 0x2103) {
    return false;
  }
  TView* mainView = RuntimeMainView();
  if (!RuntimeIsViewKindOf(mainView, RUNTIME_CLASS(TNewspaperView))) {
    FailScenario("\"event 0x2103 did not construct the newspaper view\"");
    return true;
  }
  if (run->NewspaperAdvanced()) {
    WaitForScenarioTick("\"newspaper end action did not advance to the combined map\"");
    return true;
  }
  if (!BeforeInitialNewspaperExit()) {
    return true;
  }
  TControl* endControl = static_cast<TControl*>(mainView->ResolveControlByTag(kControlTagEnd));
  if (endControl == 0 || endControl->IsActionable() == 0) {
    FailScenario("\"newspaper end control is missing or disabled\"");
    return true;
  }
  run->SetNewspaperAdvanced(true);
  run->RecordAction("activate_newspaper_end");
  endControl->HandleEvent(endControl->GetEventNumber(), endControl, 0);
  RequestAnotherDriverTick();
  return true;
}

void RuntimeScenario::ResetNewspaperAdvance() {
  run->SetNewspaperAdvanced(false);
}

void RuntimeScenario::RecordUnexpectedModalView(TView* modal) {
  char tag[5];
  FourCcText(static_cast<unsigned int>(modal->controlTag), tag);
  CString entry;
  entry.Format("{\"class\": \"%s\", \"tag\": \"%s\", \"phase\": \"%s\", \"t_ms\": %lu}",
               RuntimeClassName(modal), tag, run->PhaseName(), run->ElapsedMs());
  RuntimeJson::AppendArrayItem(run->UnexpectedModals(), entry);
}

bool RuntimeScenario::HasScenarioUiSnapshot() const {
  return !run->ScenarioUiSnapshot().IsEmpty();
}

void RuntimeScenario::CaptureScenarioUiSnapshot(int eventCode, TView* root) {
  run->ScenarioUiSnapshot() = CaptureRuntimeUiSnapshot(eventCode, root);
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
