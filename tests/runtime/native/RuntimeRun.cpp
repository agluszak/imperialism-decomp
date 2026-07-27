#include "RuntimeRun.h"

#include "RuntimeJson.h"

#include <stdlib.h>
#include <windows.h>

RuntimeRun::RuntimeRun()
    : scenario(0), step(0), finished(false), seed(1), idleTicks(0), phaseTicks(0), phaseStartMs(0),
      startMs(0), progressCounter(0), lastProgressMs(0), lastHeartbeatMs(0), phaseTimeoutMs(60000),
      selectedNationSlot(-1), mainWindowHandle(0), newspaperAdvanced(false),
      activatedEventSequence("["), handledModals("["), unexpectedModals("["), faults("["),
      actionLog("["), assertionFailures("[") {
  testName[0] = 0;
  phaseName[0] = 0;
  lastAction[0] = 0;
  resultPath[0] = 0;
  heartbeatPath[0] = 0;
  debugRecordPath[0] = 0;
  fixturePath[0] = 0;
  holdTarget[0] = 0;
  spinPhase[0] = 0;
  firstAssertionId[0] = 0;
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
  char timeoutText[16];
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_PHASE_TIMEOUT_MS", timeoutText,
                                   sizeof(timeoutText));
  if (length != 0 && length < sizeof(timeoutText)) {
    unsigned long parsed = strtoul(timeoutText, 0, 10);
    if (parsed != 0) {
      phaseTimeoutMs = parsed;
    }
  }
}

void RuntimeRun::StartScenario(RuntimeScenario* value) {
  scenario = value;
  step = 0;
  finished = false;
  idleTicks = 0;
  phaseTicks = 0;
  startMs = GetTickCount();
  phaseStartMs = startMs;
  progressCounter = 0;
  lastProgressMs = 0;
  lastHeartbeatMs = 0;
  selectedNationSlot = -1;
  mainWindowHandle = 0;
  newspaperAdvanced = false;
  lstrcpyA(phaseName, "not_started");
  lastAction[0] = 0;
  firstAssertionId[0] = 0;
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

void RuntimeRun::SetStep(RuntimeStep value, const char* phase, const char* action) {
  step = value;
  lstrcpynA(phaseName, phase, sizeof(phaseName));
  phaseTicks = 0;
  phaseStartMs = GetTickCount();
  MarkProgress(action);
  RecordAction(action);
}

void RuntimeRun::Finish() {
  finished = true;
  step = 0;
  lstrcpyA(phaseName, "finished");
}

void RuntimeRun::CountTick() {
  ++idleTicks;
  ++phaseTicks;
}

void RuntimeRun::ResetHeartbeat() {
  lastHeartbeatMs = 0;
}

void RuntimeRun::MarkProgress(const char* action) {
  lstrcpynA(lastAction, action, sizeof(lastAction));
  ++progressCounter;
  lastProgressMs = ElapsedMs();
}

void RuntimeRun::MarkFallbackProgress() {
  ++progressCounter;
  lastProgressMs = ElapsedMs();
}

void RuntimeRun::RecordAction(const char* action) {
  CString entry;
  entry.Format("{\"t_ms\": %lu, \"phase\": \"%s\", \"action\": \"%s\"}", ElapsedMs(), PhaseName(),
               action);
  RuntimeJson::AppendArrayItem(actionLog, entry);
}

void RuntimeRun::RecordAssertion(const char* assertionId, const char* failureJson, bool fatal) {
  CString entry("{\"id\": ");
  RuntimeJson::AppendString(entry, assertionId);
  entry += ", \"severity\": ";
  RuntimeJson::AppendString(entry, fatal ? "require" : "check");
  entry += ", \"message\": ";
  entry += failureJson;
  entry += "}";
  RuntimeJson::AppendArrayItem(assertionFailures, entry);
  if (firstAssertionId[0] == 0) {
    lstrcpynA(firstAssertionId, assertionId, sizeof(firstAssertionId));
    firstFailureJson = failureJson;
  }
}

RuntimeScenario* RuntimeRun::Scenario() const {
  return scenario;
}

RuntimeStep RuntimeRun::Step() const {
  return step;
}

bool RuntimeRun::IsFinished() const {
  return finished;
}

const char* RuntimeRun::TestName() const {
  return testName;
}

unsigned int RuntimeRun::Seed() const {
  return seed;
}

const char* RuntimeRun::PhaseName() const {
  return phaseName;
}

unsigned long RuntimeRun::ElapsedMs() const {
  return GetTickCount() - startMs;
}

unsigned long RuntimeRun::IdleTicks() const {
  return idleTicks;
}

unsigned long RuntimeRun::PhaseTicks() const {
  return phaseTicks;
}

unsigned long RuntimeRun::PhaseElapsedMs() const {
  return GetTickCount() - phaseStartMs;
}

unsigned long RuntimeRun::ProgressCounter() const {
  return progressCounter;
}

unsigned long RuntimeRun::LastProgressMs() const {
  return lastProgressMs;
}

unsigned long RuntimeRun::LastHeartbeatMs() const {
  return lastHeartbeatMs;
}

void RuntimeRun::SetLastHeartbeatMs(unsigned long value) {
  lastHeartbeatMs = value;
}

const char* RuntimeRun::LastAction() const {
  return lastAction;
}

unsigned long RuntimeRun::PhaseTimeoutMs() const {
  return phaseTimeoutMs;
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
  return spinPhase[0] != 0 && lstrcmpiA(spinPhase, phaseName) == 0;
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
  return assertionFailures.GetLength() > 1;
}
const char* RuntimeRun::FirstAssertionId() const {
  return firstAssertionId;
}
const char* RuntimeRun::FirstFailureJson() const {
  return firstFailureJson;
}
