#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeRun is test-only and must not be included in the production build
#endif

#include "game/mfc.h"
#include "RuntimeHarnessCore.h"
#include "parson.h"

#include <windows.h>

class RuntimeScenario;

class RuntimeRun {
public:
  RuntimeRun();
  ~RuntimeRun();

  void InitializeFromEnvironment();
  void SetDescriptor(unsigned int captureFlags);
  // Catalog-declared scenario policy (see RuntimeTestDescriptor).
  void SetScenarioPolicy(bool recordsGameFlow, const int* uiSnapshotEvents,
                         int uiSnapshotEventCount);
  bool RecordsGameFlow() const;
  bool CapturesUiTreeAt(int eventCode) const;
  bool CapturesAnyUiTree() const;
  void StartScenario(RuntimeScenario* scenario);
  void EnterPhase(const char* phase, const char* action);
  void Finish();
  void ResetHeartbeat();
  void MarkProgress(const char* action);
  void MarkFallbackProgress();
  void RecordAssertion(const char* assertionId, const char* failure, bool fatal);
  RuntimeAwaitState& AwaitState();
  const RuntimeAwaitState& AwaitState() const;

  // Takes ownership of value and replaces an existing capture with the same name.
  void SetCapture(const char* name, JSON_Value* value);
  bool HasCapture(const char* name) const;
  JSON_Object* Captures() const;

  RuntimeScenario* Scenario() const;
  bool IsFinished() const;
  const char* TestName() const;
  unsigned int Seed() const;
  const char* PhaseName() const;
  unsigned long ElapsedMs() const;
  unsigned long IdleTicks() const;
  unsigned long PhaseTicks() const;
  unsigned long PhaseElapsedMs() const;
  unsigned long ProgressCounter() const;
  unsigned long LastProgressMs() const;
  bool HeartbeatDue(unsigned long now, unsigned long interval) const;
  void SetLastHeartbeatMs(unsigned long value);
  const char* LastAction() const;

  const char* ResultPath() const;
  const char* HeartbeatPath() const;
  const char* DebugRecordPath() const;
  const char* FixturePath() const;
  bool HasFixturePath() const;
  bool HoldRequested() const;
  bool HoldAt(const char* target) const;
  bool SpinRequestedForCurrentPhase() const;
  bool RequestsCapture(unsigned int flag) const;

  short SelectedNationSlot() const;
  void SetSelectedNationSlot(short value);
  HWND MainWindowHandle() const;
  void SetMainWindowHandle(HWND value);
  bool NewspaperAdvanced() const;
  void SetNewspaperAdvanced(bool value);

  void SetRandomSetupUiSnapshot(JSON_Value* value);
  void SetStrategicMapUiSnapshot(JSON_Value* value);
  void SetScenarioUiSnapshot(JSON_Value* value);
  void SetCapitalConfirmationUiSnapshot(JSON_Value* value);
  bool HasRandomSetupUiSnapshot() const;
  bool HasStrategicMapUiSnapshot() const;
  bool HasScenarioUiSnapshot() const;
  JSON_Value* RandomSetupUiSnapshot() const;
  JSON_Value* StrategicMapUiSnapshot() const;
  JSON_Value* ScenarioUiSnapshot() const;
  JSON_Value* CapitalConfirmationUiSnapshot() const;
  CString& LastFingerprint();
  bool HasAssertionFailures() const;
  const char* FirstAssertionId() const;
  const char* FirstFailure() const;

private:
  void ClearJsonValues();
  void InitializeJsonValues();

  RuntimeScenario* scenario;
  RuntimeProgressState progress;
  RuntimeAwaitState awaitState;
  RuntimeResultAggregate resultAggregate;
  unsigned int seed;
  short selectedNationSlot;
  HWND mainWindowHandle;
  bool newspaperAdvanced;
  unsigned int captureFlags;
  bool recordsGameFlow;
  const int* uiSnapshotEvents;
  int uiSnapshotEventCount;
  char testName[64];
  char resultPath[MAX_PATH];
  char heartbeatPath[MAX_PATH];
  char debugRecordPath[MAX_PATH];
  char fixturePath[MAX_PATH];
  char holdTarget[48];
  char spinPhase[48];
  CString lastFingerprint;
  JSON_Value* capturesValue;
  JSON_Object* captures;
  JSON_Value* randomSetupUiSnapshot;
  JSON_Value* strategicMapUiSnapshot;
  JSON_Value* scenarioUiSnapshot;
  JSON_Value* capitalConfirmationUiSnapshot;
};
