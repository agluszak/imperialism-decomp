#include "RuntimeScriptBases.h"

RuntimeFlow* RandomGameScriptScenario::NavigationFlow() {
  return &randomGameFlow;
}

void RandomGameScriptScenario::RestartRandomGameAtStrategicMapEntry() {
  randomGameFlow.RestartStrategicMapEntry(*this);
}

int EasyMapScriptScenario::DifficultyLevel() const {
  return 1;
}

void EasyMapScriptScenario::OnMapReadyWithoutCapitalSelection() {
  BeginScript("running_script");
}

int IntroductoryMapScriptScenario::DifficultyLevel() const {
  return 0;
}

void IntroductoryMapScriptScenario::OnMapReadyWithoutCapitalSelection() {
  BeginScript("running_script");
}

int CombinedMapScriptScenario::DifficultyLevel() const {
  return 2;
}

void CombinedMapScriptScenario::OnCombinedMapReady() {
  BeginScript("running_script");
}

CapitalSelectionScriptScenario::CapitalSelectionScriptScenario() : scriptBegun(false) {}

int CapitalSelectionScriptScenario::DifficultyLevel() const {
  return 2;
}

void CapitalSelectionScriptScenario::OnFlowCheckpoint(RuntimeFlowCheckpoint checkpoint) {
  if (checkpoint == kRuntimeCapitalSelectionReady && !scriptBegun) {
    scriptBegun = true;
    // BeginScript takes the driver off the flow (EnterScenarioStep does that), so the flow stays
    // parked at its checkpoint until the script hands navigation back.
    BeginScript("running_script");
    return;
  }
  RandomGameScriptScenario::OnFlowCheckpoint(checkpoint);
}

void CapitalSelectionScriptScenario::OnCombinedMapReady() {
  ResumeScript("running_script");
}

bool LoadedMapScriptScenario::RequiresFixture() const {
  return true;
}

RuntimeFlow* LoadedMapScriptScenario::NavigationFlow() {
  return &loadGameFlow;
}

void LoadedMapScriptScenario::OnCombinedMapReady() {
  BeginScript("running_script");
}

bool ManagersReadyScriptScenario::RequiresMainWindow() const {
  return false;
}

void ManagersReadyScriptScenario::OnManagersReady() {
  // Deliberately does not call the base: the base requires a navigation flow, and this base
  // exists precisely for scenarios that need no screen.
  BeginScript("running_script");
}
