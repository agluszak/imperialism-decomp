#pragma once

#include "flows/RuntimeFlow.h"

class MainMenuFlow : public RuntimeFlow {
public:
  MainMenuFlow();

  void Start(RuntimeScenario& scenario) override;
  RuntimeFlowStatus Tick(RuntimeScenario& scenario) override;
  RuntimeFlowCheckpoint Checkpoint() const override;
  void ContinueFromCheckpoint() override;

private:
  enum Phase { kWaitingForMainMenu, kAtCheckpoint, kComplete };

  Phase phase;
  RuntimeFlowCheckpoint checkpoint;
};
