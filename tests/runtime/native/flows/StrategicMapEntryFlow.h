#pragma once

#include "flows/RuntimeFlow.h"

class StrategicMapEntryFlow : public RuntimeFlow {
public:
  StrategicMapEntryFlow();

  void Start(RuntimeScenario& scenario) override;
  RuntimeFlowStatus Advance(RuntimeScenario& scenario) override;
  void ObserveTurnEvent(RuntimeScenario& scenario, int eventCode) override;
  RuntimeFlowCheckpoint Checkpoint() const override;
  void ContinueFromCheckpoint() override;

private:
  enum Phase {
    kWaitingForDirectMap,
    kWaitingForCapitalMap,
    kWaitingForCapitalPromptDismissal,
    kSelectingCapitalSite,
    kWaitingForCapitalConfirmation,
    kWaitingForCombinedMap,
    kAtCheckpoint,
    kComplete
  };

  RuntimeFlowStatus ReachCheckpoint(RuntimeFlowCheckpoint value);
  void Enter(RuntimeScenario& scenario, Phase next, const char* phaseName, const char* action);

  Phase phase;
  Phase phaseAfterCheckpoint;
  RuntimeFlowCheckpoint checkpoint;
};
