#pragma once

#include "RuntimeTestCase.h"

class CString;
class RuntimeContext;
class TView;

// Shared protocol and navigation flow for native runtime tests. Concrete tests
// own their terminal phases and mutable scenario state; adding a test does not
// extend a central completion enum.
class RuntimeScenario : public RuntimeTestCase {
public:
  void Start(RuntimeContext& context) override;
  void Tick(RuntimeContext& context) override;
  void ObserveTurnEvent(RuntimeContext& context, int eventCode) override;
  void ObserveBuiltUiTree(RuntimeContext& context, int eventCode, TView* root) override;
  void Pulse(RuntimeContext& context) override;
  unsigned int RandomSeed(RuntimeContext& context) override;
  void FailHarness(RuntimeContext& context, const char* failure) override;

  virtual const char* Name() const = 0;
  virtual bool RequiresMainWindow() const;
  virtual bool RequiresFixture() const;
  virtual bool UsesRandomGameFlow() const;
  virtual int DifficultyLevel() const;
  virtual bool RecordsGameFlow() const;
  virtual bool RequiresScenarioUiSnapshot() const;
  virtual bool BeforeInitialNewspaperExit();

  virtual void OnManagersReady();
  virtual void OnMapReadyWithoutCapitalSelection();
  virtual void OnCombinedMapReady();
  virtual void RunScenarioStep();
  virtual void ObserveScenarioUiTree(int eventCode, TView* root);

protected:
  void Pass();
  void FailScenario(const char* failure);
  bool WaitForScenarioTick(const char* failure);
  void RequestScenarioTick();
  void EnterScenarioStep(const char* phaseName, const char* action);
  void StartRandomGameFlow();

  TView* CurrentMainView() const;
  unsigned long ScenarioPhaseTicks() const;
  unsigned long ScenarioPhaseElapsedMs() const;
  const char* FixturePath() const;
  void SetSelectedNation(short nationSlot);
  bool AdvanceNewspaperIfNeeded();
  void ResetNewspaperAdvance();
  void RecordUnexpectedModalView(TView* modal);
  bool HasScenarioUiSnapshot() const;
  void CaptureScenarioUiSnapshot(int eventCode, TView* root);
  bool HoldAtScenarioScreen(const char* screenName) const;
  // Per-class serialization round-trip findings, emitted verbatim into the result file
  // under "serialization_roundtrip" (null when no scenario recorded any).
  void RecordSerializationRoundtripReport(const CString& reportJson);
};
