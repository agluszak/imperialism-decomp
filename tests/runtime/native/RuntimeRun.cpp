#include "RuntimeRun.h"

#include "RuntimeJson.h"

#include <stdlib.h>
#include <windows.h>

RuntimeRun::RuntimeRun()
    : scenario(0), seed(1), selectedNationSlot(-1), mainWindowHandle(0), newspaperAdvanced(false),
      snapshotFlags(0), recordsGameFlow(false), uiSnapshotEvents(0), uiSnapshotEventCount(0),
      activatedEventSequence("["), handledModals("["), unexpectedModals("["), faults("["),
      actionLog("["), assertionFailures("[") {
  testName[0] = 0;
  resultPath[0] = 0;
  heartbeatPath[0] = 0;
  debugRecordPath[0] = 0;
  fixturePath[0] = 0;
  holdTarget[0] = 0;
  spinPhase[0] = 0;
  lstrcpyA(evidenceKind, "internal_invariant");
}

void RuntimeRun::SetDescriptor(unsigned int flags, const char* kind) {
  snapshotFlags = flags;
  lstrcpynA(evidenceKind, kind, sizeof(evidenceKind));
}

void RuntimeRun::SetScenarioPolicy(bool records, const int* events, int eventCount) {
  recordsGameFlow = records;
  uiSnapshotEvents = events;
  uiSnapshotEventCount = eventCount;
}

bool RuntimeRun::RecordsGameFlow() const {
  return recordsGameFlow;
}

bool RuntimeRun::CapturesUiTreeAt(int eventCode) const {
  for (int index = 0; index < uiSnapshotEventCount; ++index) {
    if (uiSnapshotEvents[index] == eventCode) {
      return true;
    }
  }
  return false;
}

bool RuntimeRun::CapturesAnyUiTree() const {
  return uiSnapshotEventCount > 0;
}

void RuntimeRun::InitializeFromEnvironment() {
  DWORD length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST", testName, sizeof(testName));
  if (length == 0 || length >= sizeof(testName)) {
    lstrcpyA(testName, "boot_managers");
  }
  char seedText[32];
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_SEED", seedText, sizeof(seedText));
  if (length != 0 && length < sizeof(seedText)) {
    unsigned long parsed = strtoul(seedText, 0, 10);
    if (parsed != 0) {
      seed = static_cast<unsigned int>(parsed);
    }
  }
  length =
      GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_RESULT", resultPath, sizeof(resultPath));
  if (length == 0 || length >= sizeof(resultPath)) {
    lstrcpyA(resultPath, "runtime-test-result.json");
  }
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_HEARTBEAT", heartbeatPath,
                                   sizeof(heartbeatPath));
  if (length >= sizeof(heartbeatPath)) {
    heartbeatPath[0] = 0;
  }
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_DEBUG_RECORD", debugRecordPath,
                                   sizeof(debugRecordPath));
  if (length >= sizeof(debugRecordPath)) {
    debugRecordPath[0] = 0;
  }
  length =
      GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_FIXTURE", fixturePath, sizeof(fixturePath));
  if (length >= sizeof(fixturePath)) {
    fixturePath[0] = 0;
  }
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_HOLD", holdTarget, sizeof(holdTarget));
  if (length >= sizeof(holdTarget)) {
    holdTarget[0] = 0;
  }
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_SPIN", spinPhase, sizeof(spinPhase));
  if (length >= sizeof(spinPhase)) {
    spinPhase[0] = 0;
  }
}

void RuntimeRun::StartScenario(RuntimeScenario* value) {
  scenario = value;
  progress.Reset(GetTickCount());
  awaitState.Clear();
  resultAggregate.Reset();
  selectedNationSlot = -1;
  mainWindowHandle = 0;
  newspaperAdvanced = false;
  firstFailureJson.Empty();
  randomSetupUiSnapshot.Empty();
  strategicMapUiSnapshot.Empty();
  scenarioUiSnapshot.Empty();
  capitalConfirmationUiSnapshot.Empty();
  activatedEventSequence = "[";
  handledModals = "[";
  unexpectedModals = "[";
  faults = "[";
  actionLog = "[";
  lastFingerprint.Empty();
  mapStateJson.Empty();
  serializationRoundtripJson.Empty();
  assertionFailures = "[";
}

void RuntimeRun::EnterPhase(const char* phase, const char* action) {
  progress.EnterPhase(phase, action, GetTickCount());
  RecordAction(action);
}

void RuntimeRun::Finish() {
  progress.Finish();
}

void RuntimeRun::ResetHeartbeat() {
  progress.ResetHeartbeat();
}

void RuntimeRun::MarkProgress(const char* action) {
  progress.MarkProgress(action, GetTickCount());
}

void RuntimeRun::MarkFallbackProgress() {
  progress.MarkFallbackProgress(GetTickCount());
}

void RuntimeRun::RecordAction(const char* action) {
  CString entry;
  entry.Format("{\"t_ms\": %lu, \"phase\": \"%s\", \"action\": \"%s\"}", ElapsedMs(), PhaseName(),
               action);
  RuntimeJson::AppendArrayItem(actionLog, entry);
}

RuntimeAwaitState& RuntimeRun::AwaitState() {
  return awaitState;
}

const RuntimeAwaitState& RuntimeRun::AwaitState() const {
  return awaitState;
}

void RuntimeRun::RecordAssertion(const char* assertionId, const char* failureJson, bool fatal) {
  resultAggregate.RecordAssertion(assertionId, failureJson, fatal);
  CString entry("{\"id\": ");
  RuntimeJson::AppendString(entry, assertionId);
  entry += ", \"severity\": ";
  RuntimeJson::AppendString(entry, fatal ? "require" : "check");
  entry += ", \"message\": ";
  entry += failureJson;
  entry += "}";
  RuntimeJson::AppendArrayItem(assertionFailures, entry);
  if (resultAggregate.FailureCount() == 1) {
    firstFailureJson = failureJson;
  }
}

RuntimeScenario* RuntimeRun::Scenario() const {
  return scenario;
}

bool RuntimeRun::IsFinished() const {
  return progress.IsFinished();
}

const char* RuntimeRun::TestName() const {
  return testName;
}

unsigned int RuntimeRun::Seed() const {
  return seed;
}

const char* RuntimeRun::PhaseName() const {
  return progress.PhaseName();
}

unsigned long RuntimeRun::ElapsedMs() const {
  return progress.ElapsedMs(GetTickCount());
}

unsigned long RuntimeRun::IdleTicks() const {
  return progress.IdleTicks();
}

unsigned long RuntimeRun::PhaseTicks() const {
  return progress.PhaseTicks();
}

unsigned long RuntimeRun::PhaseElapsedMs() const {
  return progress.PhaseElapsedMs(GetTickCount());
}

unsigned long RuntimeRun::ProgressCounter() const {
  return progress.ProgressCounter();
}

unsigned long RuntimeRun::LastProgressMs() const {
  return progress.LastProgressMs();
}

bool RuntimeRun::HeartbeatDue(unsigned long now, unsigned long interval) const {
  return progress.HeartbeatDue(now, interval);
}

void RuntimeRun::SetLastHeartbeatMs(unsigned long value) {
  progress.MarkHeartbeatWritten(value);
}

const char* RuntimeRun::LastAction() const {
  return progress.LastAction();
}

const char* RuntimeRun::ResultPath() const {
  return resultPath;
}
const char* RuntimeRun::HeartbeatPath() const {
  return heartbeatPath;
}
const char* RuntimeRun::DebugRecordPath() const {
  return debugRecordPath;
}
const char* RuntimeRun::FixturePath() const {
  return fixturePath;
}
bool RuntimeRun::HasFixturePath() const {
  return fixturePath[0] != 0;
}
bool RuntimeRun::HoldRequested() const {
  return holdTarget[0] != 0;
}
bool RuntimeRun::HoldAt(const char* target) const {
  return holdTarget[0] != 0 && lstrcmpiA(holdTarget, target) == 0;
}
bool RuntimeRun::SpinRequestedForCurrentPhase() const {
  return spinPhase[0] != 0 && lstrcmpiA(spinPhase, progress.PhaseName()) == 0;
}
bool RuntimeRun::CapturesSnapshot(unsigned int flag) const {
  return (snapshotFlags & flag) != 0;
}
const char* RuntimeRun::EvidenceKind() const {
  return evidenceKind;
}

short RuntimeRun::SelectedNationSlot() const {
  return selectedNationSlot;
}
void RuntimeRun::SetSelectedNationSlot(short value) {
  selectedNationSlot = value;
}
HWND RuntimeRun::MainWindowHandle() const {
  return mainWindowHandle;
}
void RuntimeRun::SetMainWindowHandle(HWND value) {
  mainWindowHandle = value;
}
bool RuntimeRun::NewspaperAdvanced() const {
  return newspaperAdvanced;
}
void RuntimeRun::SetNewspaperAdvanced(bool value) {
  newspaperAdvanced = value;
}

CString& RuntimeRun::RandomSetupUiSnapshot() {
  return randomSetupUiSnapshot;
}
CString& RuntimeRun::StrategicMapUiSnapshot() {
  return strategicMapUiSnapshot;
}
CString& RuntimeRun::ScenarioUiSnapshot() {
  return scenarioUiSnapshot;
}
CString& RuntimeRun::CapitalConfirmationUiSnapshot() {
  return capitalConfirmationUiSnapshot;
}
CString& RuntimeRun::ActivatedEventSequence() {
  return activatedEventSequence;
}
CString& RuntimeRun::HandledModals() {
  return handledModals;
}
CString& RuntimeRun::UnexpectedModals() {
  return unexpectedModals;
}
CString& RuntimeRun::Faults() {
  return faults;
}
CString& RuntimeRun::ActionLog() {
  return actionLog;
}
CString& RuntimeRun::LastFingerprint() {
  return lastFingerprint;
}
CString& RuntimeRun::MapStateJson() {
  return mapStateJson;
}
CString& RuntimeRun::SerializationRoundtripJson() {
  return serializationRoundtripJson;
}

CString RuntimeRun::AssertionFailuresJson() const {
  CString result(assertionFailures);
  result += ']';
  return result;
}

bool RuntimeRun::HasAssertionFailures() const {
  return resultAggregate.HasFailures();
}
const char* RuntimeRun::FirstAssertionId() const {
  return resultAggregate.FirstAssertionId();
}
const char* RuntimeRun::FirstFailureJson() const {
  return firstFailureJson;
}
