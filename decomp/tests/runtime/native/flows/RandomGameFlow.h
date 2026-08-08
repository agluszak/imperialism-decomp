#pragma once

#include "flows/RuntimeFlow.h"
#include "flows/MainMenuFlow.h"
#include "flows/RandomSetupFlow.h"
#include "flows/StrategicMapEntryFlow.h"
#include "scenarios/RuntimeScenario.h"

class RandomGameFlow : public RuntimeFlow {
public:
  RandomGameFlow();

  void Start(RuntimeScenario& scenario) override;
  RuntimeFlowStatus Advance(RuntimeScenario& scenario) override;
  void ObserveTurnEvent(RuntimeScenario& scenario, int eventCode) override;
  RuntimeFlowCheckpoint Checkpoint() const override;
  void ContinueFromCheckpoint() override;
  void RestartStrategicMapEntry(RuntimeScenario& scenario);

private:
  enum Phase { kMainMenu, kRandomSetup, kStrategicMapEntry, kComplete };

  MainMenuFlow mainMenuFlow;
  RandomSetupFlow randomSetupFlow;
  StrategicMapEntryFlow strategicMapEntryFlow;
  Phase phase;
};

class RandomGameScenario : public RuntimeScenario {
protected:
  RuntimeFlow* NavigationFlow() override;
  void RestartRandomGameAtStrategicMapEntry();

private:
  RandomGameFlow randomGameFlow;
};
