#include "RuntimeRun.h"

#include <stdlib.h>
#include <windows.h>

namespace {

void FreeJsonValue(JSON_Value*& value) {
  if (value != 0) {
    json_value_free(value);
    value = 0;
  }
}

void ReplaceJsonValue(JSON_Value*& target, JSON_Value* value) {
  FreeJsonValue(target);
  target = value;
}

} // namespace

RuntimeRun::RuntimeRun()
    : scenario(0), seed(1), selectedNationSlot(-1), mainWindowHandle(0), newspaperAdvanced(false),
      captureFlags(0), recordsGameFlow(false), uiSnapshotEvents(0), uiSnapshotEventCount(0),
      capturesValue(0), captures(0), randomSetupUiSnapshot(0), strategicMapUiSnapshot(0),
      scenarioUiSnapshot(0), capitalConfirmationUiSnapshot(0) {
  testName[0] = 0;
  resultPath[0] = 0;
  heartbeatPath[0] = 0;
  debugRecordPath[0] = 0;
  fixturePath[0] = 0;
  holdTarget[0] = 0;
  spinPhase[0] = 0;
  InitializeJsonValues();
}

RuntimeRun::~RuntimeRun() {
  ClearJsonValues();
}

void RuntimeRun::ClearJsonValues() {
  FreeJsonValue(capturesValue);
  captures = 0;
  FreeJsonValue(randomSetupUiSnapshot);
  FreeJsonValue(strategicMapUiSnapshot);
  FreeJsonValue(scenarioUiSnapshot);
  FreeJsonValue(capitalConfirmationUiSnapshot);
}

void RuntimeRun::InitializeJsonValues() {
  capturesValue = json_value_init_object();
  captures = capturesValue != 0 ? json_value_get_object(capturesValue) : 0;
}

void RuntimeRun::SetDescriptor(unsigned int flags) {
  captureFlags = flags;
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
  lastFingerprint.Empty();
  ClearJsonValues();
  InitializeJsonValues();
}

void RuntimeRun::EnterPhase(const char* phase, const char* action) {
  progress.EnterPhase(phase, action, GetTickCount());
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

RuntimeAwaitState& RuntimeRun::AwaitState() {
  return awaitState;
}

const RuntimeAwaitState& RuntimeRun::AwaitState() const {
  return awaitState;
}

void RuntimeRun::RecordAssertion(const char* assertionId, const char* failure, bool fatal) {
  const char* message = failure != 0 ? failure : "";
  resultAggregate.RecordAssertion(assertionId, message, fatal);
}

void RuntimeRun::SetCapture(const char* name, JSON_Value* value) {
  if (captures == 0 || name == 0 || value == 0 ||
      json_object_set_value(captures, name, value) != JSONSuccess) {
    json_value_free(value);
  }
}

bool RuntimeRun::HasCapture(const char* name) const {
  return captures != 0 && name != 0 && json_object_has_value(captures, name) != 0;
}

JSON_Object* RuntimeRun::Captures() const {
  return captures;
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

bool RuntimeRun::RequestsCapture(unsigned int flag) const {
  return (captureFlags & flag) != 0;
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

void RuntimeRun::SetRandomSetupUiSnapshot(JSON_Value* value) {
  ReplaceJsonValue(randomSetupUiSnapshot, value);
}

void RuntimeRun::SetStrategicMapUiSnapshot(JSON_Value* value) {
  ReplaceJsonValue(strategicMapUiSnapshot, value);
}

void RuntimeRun::SetScenarioUiSnapshot(JSON_Value* value) {
  ReplaceJsonValue(scenarioUiSnapshot, value);
}

void RuntimeRun::SetCapitalConfirmationUiSnapshot(JSON_Value* value) {
  ReplaceJsonValue(capitalConfirmationUiSnapshot, value);
}

bool RuntimeRun::HasRandomSetupUiSnapshot() const {
  return randomSetupUiSnapshot != 0;
}

bool RuntimeRun::HasStrategicMapUiSnapshot() const {
  return strategicMapUiSnapshot != 0;
}

bool RuntimeRun::HasScenarioUiSnapshot() const {
  return scenarioUiSnapshot != 0;
}

JSON_Value* RuntimeRun::RandomSetupUiSnapshot() const {
  return randomSetupUiSnapshot;
}

JSON_Value* RuntimeRun::StrategicMapUiSnapshot() const {
  return strategicMapUiSnapshot;
}

JSON_Value* RuntimeRun::ScenarioUiSnapshot() const {
  return scenarioUiSnapshot;
}

JSON_Value* RuntimeRun::CapitalConfirmationUiSnapshot() const {
  return capitalConfirmationUiSnapshot;
}

CString& RuntimeRun::LastFingerprint() {
  return lastFingerprint;
}

bool RuntimeRun::HasAssertionFailures() const {
  return resultAggregate.HasFailures();
}

const char* RuntimeRun::FirstAssertionId() const {
  return resultAggregate.FirstAssertionId();
}

const char* RuntimeRun::FirstFailure() const {
  return resultAggregate.FirstFailure();
}
