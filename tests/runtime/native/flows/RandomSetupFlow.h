#pragma once

#include "flows/RuntimeFlow.h"

class RandomSetupFlow : public RuntimeFlow {
public:
  RandomSetupFlow();

  void Start(RuntimeScenario& scenario) override;
  RuntimeFlowStatus Advance(RuntimeScenario& scenario) override;
  RuntimeFlowCheckpoint Checkpoint() const override;
  void ContinueFromCheckpoint() override;

private:
  enum Phase {
    kWaitingForRandomSetup,
    kSettingCountryName,
    kSelectingDifficulty,
    kActivatingOkay,
    kAtCheckpoint,
    kComplete
  };

  Phase phase;
  RuntimeFlowCheckpoint checkpoint;
};
