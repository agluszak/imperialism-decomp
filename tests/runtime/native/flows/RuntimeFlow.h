#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeFlow is test-only and must not be included in the production build
#endif

#include "compat.h"

class RuntimeScenario;

enum RuntimeFlowStatus { kRuntimeFlowRunning, kRuntimeFlowCheckpoint, kRuntimeFlowComplete };

enum RuntimeFlowCheckpoint {
  kRuntimeNoCheckpoint,
  kRuntimeMainMenuRandomGameRequested,
  kRuntimeRandomSetupAccepted,
  kRuntimeCapitalSelectionReady,
  kRuntimeMapReadyWithoutCapitalSelection,
  kRuntimeCombinedMapReady,
  kRuntimeLoadedMapReady
};

class RuntimeFlow {
public:
  virtual ~RuntimeFlow() {}
  virtual void Start(RuntimeScenario& scenario) = 0;
  virtual RuntimeFlowStatus Tick(RuntimeScenario& scenario) = 0;
  virtual void ObserveTurnEvent(RuntimeScenario&, int) {}
  virtual RuntimeFlowCheckpoint Checkpoint() const = 0;
  virtual void ContinueFromCheckpoint() = 0;
};
