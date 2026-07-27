#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeRun is test-only and must not be included in the production build
#endif

#include "game/mfc.h"
#include "RuntimeHarnessCore.h"

#include <windows.h>

class RuntimeScenario;

class RuntimeRun {
public:
  RuntimeRun();

  void InitializeFromEnvironment();
  void SetDescriptor(unsigned int snapshotFlags, const char* evidenceKind);
  void StartScenario(RuntimeScenario* scenario);
  void EnterPhase(const char* phase, const char* action);
  void Finish();
  void CountTick();
  void ResetHeartbeat();
  void MarkProgress(const char* action);
  void MarkFallbackProgress();
  void RecordAction(const char* action);
  void RecordAssertion(const char* assertionId, const char* failureJson, bool fatal);

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
  unsigned long PhaseTimeoutMs() const;

  const char* ResultPath() const;
  const char* HeartbeatPath() const;
  const char* DebugRecordPath() const;
  const char* FixturePath() const;
  bool HasFixturePath() const;
  bool HoldRequested() const;
  bool HoldAt(const char* target) const;
  bool SpinRequestedForCurrentPhase() const;
  bool CapturesSnapshot(unsigned int flag) const;
  const char* EvidenceKind() const;

  short SelectedNationSlot() const;
  void SetSelectedNationSlot(short value);
  HWND MainWindowHandle() const;
  void SetMainWindowHandle(HWND value);
  bool NewspaperAdvanced() const;
  void SetNewspaperAdvanced(bool value);

  CString& RandomSetupUiSnapshot();
  CString& StrategicMapUiSnapshot();
  CString& ScenarioUiSnapshot();
  CString& CapitalConfirmationUiSnapshot();
  CString& ActivatedEventSequence();
  CString& HandledModals();
  CString& UnexpectedModals();
  CString& Faults();
  CString& ActionLog();
  CString& LastFingerprint();
  CString& MapStateJson();
  CString& SerializationRoundtripJson();
  CString AssertionFailuresJson() const;
  bool HasAssertionFailures() const;
  const char* FirstAssertionId() const;
  const char* FirstFailureJson() const;

private:
  RuntimeScenario* scenario;
  RuntimeProgressState progress;
  RuntimeResultAggregate resultAggregate;
  unsigned int seed;
  unsigned long phaseTimeoutMs;
  short selectedNationSlot;
  HWND mainWindowHandle;
  bool newspaperAdvanced;
  unsigned int snapshotFlags;
  char testName[64];
  char resultPath[MAX_PATH];
  char heartbeatPath[MAX_PATH];
  char debugRecordPath[MAX_PATH];
  char fixturePath[MAX_PATH];
  char holdTarget[48];
  char spinPhase[48];
  char evidenceKind[32];
  CString firstFailureJson;
  CString randomSetupUiSnapshot;
  CString strategicMapUiSnapshot;
  CString scenarioUiSnapshot;
  CString capitalConfirmationUiSnapshot;
  CString activatedEventSequence;
  CString handledModals;
  CString unexpectedModals;
  CString faults;
  CString actionLog;
  CString lastFingerprint;
  CString mapStateJson;
  CString serializationRoundtripJson;
  CString assertionFailures;
};
