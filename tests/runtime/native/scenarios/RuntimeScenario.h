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
  void FailScenario(const char* failure);
  bool Require(const char* assertionId, bool condition, const char* failure);
  bool Check(const char* assertionId, bool condition, const char* failure);
  bool FinishChecks();
  void AwaitUiChange(const char* failure);
  void Await(unsigned int observationKinds, const char* failure);
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
  bool HoldAtScenarioScreen(const char* screenName) const;
  // Per-class serialization round-trip findings, emitted verbatim into the result file
  // under "serialization_roundtrip" (null when no scenario recorded any).
  void RecordSerializationRoundtripReport(const CString& reportJson);

private:
  enum DriverState { kWaitingForManagers, kRunningFlow, kRunningScenario };

  void AdvanceDriver(unsigned int observationKinds);
  void AdvanceWaitingForManagers();
  void Finish(const char* status, const char* failure);
  void EnterFlowPhase(const char* phaseName, const char* action);
  RuntimeRun& RunState() const;

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
