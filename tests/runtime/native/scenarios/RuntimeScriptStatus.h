#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeScriptStatus is test-only and must not be included in the production build
#endif

// What one advance of a script fragment reported. A fragment is a reusable piece of a
// linear script (an end-turn sequence, a save/load sequence) that owns its own program
// counter, so unlike a scenario's Script() it cannot yield by returning void -- the caller
// has to know whether to yield or carry on.
//
// Separate header so RuntimeScriptMacros.h can be included by a fragment that has no reason
// to see RuntimeScriptScenario.
enum RuntimeScriptStatus {
  // Yielded mid-sequence. The fragment has armed its own wait; the caller must return.
  kRuntimeScriptRunning,
  // The sequence finished. The caller continues with the next statement.
  kRuntimeScriptComplete,
  // The fragment failed the scenario. The caller must return; the run is already finished.
  kRuntimeScriptFailed
};
