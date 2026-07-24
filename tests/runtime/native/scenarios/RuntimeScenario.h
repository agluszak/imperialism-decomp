#pragma once

#include "RuntimeTestCase.h"

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
  unsigned int RandomSeed(RuntimeContext& context) override;

  virtual const char* Name() const = 0;
  virtual bool RequiresMainWindow() const;
  virtual bool RequiresFixture() const;
  virtual bool UsesRandomGameFlow() const;
  virtual bool UsesEasyDifficulty() const;
  virtual bool RecordsGameFlow() const;
  virtual bool RequiresCityUiSnapshot() const;

  virtual void OnManagersReady();
  virtual void OnEasyMapReady();
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
  const char* FixturePath() const;
  void SetSelectedNation(short nationSlot);
  bool AdvanceNewspaperIfNeeded();
  void ResetNewspaperAdvance();
  void RecordUnexpectedModalView(TView* modal);
  bool HasCityUiSnapshot() const;
  void CaptureCityUiSnapshot(int eventCode, TView* root);
};
