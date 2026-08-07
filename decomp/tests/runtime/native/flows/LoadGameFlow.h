#pragma once

#include "flows/RuntimeFlow.h"
#include "scenarios/RuntimeScenario.h"

class LoadGameFlow : public RuntimeFlow {
public:
  LoadGameFlow();

  void Start(RuntimeScenario& scenario) override;
  RuntimeFlowStatus Advance(RuntimeScenario& scenario) override;
  RuntimeFlowCheckpoint Checkpoint() const override;
  void ContinueFromCheckpoint() override;

private:
  enum Phase { kOpenFixture, kWaitForMap, kAtCheckpoint, kComplete };

  Phase phase;
  RuntimeFlowCheckpoint checkpoint;
};

class LoadGameScenario : public RuntimeScenario {
protected:
  RuntimeFlow* NavigationFlow() override;

private:
  LoadGameFlow loadGameFlow;
};
