#include "RandomGameFlow.h"

RandomGameFlow::RandomGameFlow() : phase(kComplete) {}

void RandomGameFlow::Start(RuntimeScenario& scenario) {
  phase = kMainMenu;
  mainMenuFlow.Start(scenario);
}

RuntimeFlowStatus RandomGameFlow::Tick(RuntimeScenario& scenario) {
  if (phase == kMainMenu) {
    RuntimeFlowStatus status = mainMenuFlow.Tick(scenario);
    if (status != kRuntimeFlowCheckpoint) {
      return status;
    }
    mainMenuFlow.ContinueFromCheckpoint();
    phase = kRandomSetup;
    randomSetupFlow.Start(scenario);
    return kRuntimeFlowRunning;
  }
  if (phase == kRandomSetup) {
    RuntimeFlowStatus status = randomSetupFlow.Tick(scenario);
    if (status != kRuntimeFlowCheckpoint) {
      return status;
    }
    randomSetupFlow.ContinueFromCheckpoint();
    phase = kStrategicMapEntry;
    strategicMapEntryFlow.Start(scenario);
    return kRuntimeFlowRunning;
  }
  if (phase == kStrategicMapEntry) {
    return strategicMapEntryFlow.Tick(scenario);
  }
  return kRuntimeFlowComplete;
}

void RandomGameFlow::ObserveTurnEvent(RuntimeScenario& scenario, int eventCode) {
  if (phase == kStrategicMapEntry) {
    strategicMapEntryFlow.ObserveTurnEvent(scenario, eventCode);
  }
}

RuntimeFlowCheckpoint RandomGameFlow::Checkpoint() const {
  if (phase == kMainMenu) {
    return mainMenuFlow.Checkpoint();
  }
  if (phase == kRandomSetup) {
    return randomSetupFlow.Checkpoint();
  }
  if (phase == kStrategicMapEntry) {
    return strategicMapEntryFlow.Checkpoint();
  }
  return kRuntimeNoCheckpoint;
}

void RandomGameFlow::ContinueFromCheckpoint() {
  if (phase == kStrategicMapEntry) {
    strategicMapEntryFlow.ContinueFromCheckpoint();
  }
}

void RandomGameFlow::RestartStrategicMapEntry(RuntimeScenario& scenario) {
  phase = kStrategicMapEntry;
  strategicMapEntryFlow.Start(scenario);
}

RuntimeFlow* RandomGameScenario::NavigationFlow() {
  return &randomGameFlow;
}

void RandomGameScenario::RestartRandomGameAtStrategicMapEntry() {
  randomGameFlow.RestartStrategicMapEntry(*this);
}
