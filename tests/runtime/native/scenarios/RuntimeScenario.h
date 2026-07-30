#pragma once

#ifndef IMPERIALISM_RUNTIME_SCENARIO_H
#define IMPERIALISM_RUNTIME_SCENARIO_H

#include "RuntimeTestCase.h"
#include "flows/RuntimeFlow.h"

class CString;
class RuntimeContext;
class RuntimeRun;
class MainMenuFlow;
class RandomSetupFlow;
class StrategicMapEntryFlow;
class RandomGameFlow;
class LoadGameFlow;
class TView;

// Shared protocol and navigation flow for native runtime tests. Concrete tests
// own their terminal phases and mutable scenario state; adding a test does not
// extend a central completion enum.
class RuntimeScenario : public RuntimeTestCase {
public:
  RuntimeScenario();
  void Start(RuntimeContext& context) override;
  void Observe(RuntimeContext& context, unsigned int observationKinds) override;
  void ObserveTurnEvent(RuntimeContext& context, int eventCode) override;
  void ObserveBuiltUiTree(RuntimeContext& context, int eventCode, TView* root) override;
  void Pulse(RuntimeContext& context) override;
  unsigned int RandomSeed(RuntimeContext& context) override;
  void FailHarness(RuntimeContext& context, const char* failure) override;

  virtual bool RequiresMainWindow() const;
  virtual bool RequiresFixture() const;
  virtual int DifficultyLevel() const;
  virtual bool RecordsGameFlow() const;
  virtual bool RequiresScenarioUiSnapshot() const;
  virtual bool BeforeInitialNewspaperExit();

  virtual void OnManagersReady();
  virtual void OnMapReadyWithoutCapitalSelection();
  virtual void OnCombinedMapReady();
  virtual void AdvanceScenario();
  virtual void ObserveScenarioUiTree(int eventCode, TView* root);

protected:
  virtual RuntimeFlow* NavigationFlow();
  virtual void OnFlowCheckpoint(RuntimeFlowCheckpoint checkpoint);
  void Pass();
  // `failure` is a pre-escaped JSON fragment (call sites write "\"text\""). Prefer
  // FailScenarioText for anything new: it takes plain text and escapes it once here
  // instead of at every call site.
  void FailScenario(const char* failure);
  void FailScenarioText(const char* failure);
  // As above, but naming the assertion rather than letting it default to the phase name. A
  // failure's identity should be the requirement that failed -- that is what an expected-failure
  // signature and a triage search key off.
  void FailScenarioTextAs(const char* assertionId, const char* failure);
  bool Require(const char* assertionId, bool condition, const char* failure);
  bool Check(const char* assertionId, bool condition, const char* failure);
  bool FinishChecks();
  // `description` is plain text naming what the scenario is waiting for; it is published
  // in the heartbeat and the result file, so a stalled run says what it expected.
  void AwaitUiChange(const char* description);
  void Await(unsigned int observationKinds, const char* description);
  // The script layer's form: carries the awaited expression and its source location.
  void AwaitAt(unsigned int observationKinds, const char* expression, const char* file, int line);
  void ContinueAfterAction();
  void EnterScenarioStep(const char* phaseName, const char* action);

  TView* CurrentMainView() const;
  const char* FixturePath() const;
  void SetSelectedNation(short nationSlot);
  bool AdvanceNewspaperIfNeeded();
  void ResetNewspaperAdvance();
  void RecordHandledModal(const char* label);
  void RecordUnexpectedModalView(TView* modal);
  bool HasScenarioUiSnapshot() const;
  void CaptureScenarioUiSnapshot(int eventCode, TView* root);
  // Snapshot whatever screen is up, for a scenario whose interesting screen is the one it is
  // standing on rather than one it observed being built.
  void CaptureCurrentScreenSnapshot();
  bool HoldAtScenarioScreen(const char* screenName) const;
  // The run being executed. Subclasses need it to read the phase name and the armed wait
  // when building a failure diagnostic; flows already reach it through friendship.
  RuntimeRun& RunState() const;
  // Per-class serialization round-trip findings, emitted verbatim into the result file
  // under "serialization_roundtrip" (null when no scenario recorded any).
  void RecordSerializationRoundtripReport(const CString& reportJson);

private:
  enum DriverState { kWaitingForManagers, kRunningFlow, kRunningScenario };

  void AdvanceDriver(unsigned int observationKinds);
  void AdvanceWaitingForManagers();
  void Finish(const char* status, const char* failure);
  void EnterFlowPhase(const char* phaseName, const char* action);

  RuntimeRun* run;
  RuntimeFlow* activeFlow;
  DriverState driverState;
  unsigned int awaitedObservations;
  bool advancing;

  friend class RandomGameFlow;
  friend class MainMenuFlow;
  friend class RandomSetupFlow;
  friend class StrategicMapEntryFlow;
  friend class LoadGameFlow;
};

#endif
