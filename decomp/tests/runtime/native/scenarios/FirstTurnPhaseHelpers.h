#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error FirstTurnPhaseHelpers is test-only and must not be included in the production build
#endif

#include "RuntimeRun.h"
#include "screens/RuntimeActionResult.h"

// Shared first-turn phase chain from the loaded beginning-save fixture (phase 5).
// expectedSequence lists the phase codes produced by successive AdvanceGlobalTurnStateMachine
// calls after forcing turnStateCode to 6. Stops once current phase equals targetPhase.
RuntimeActionResult AdvanceFirstTurnToPhase(const int* expectedSequence, int expectedCount,
                                            int targetPhase);

// Standard before / void-case / after capture for one turn-step differential.
RuntimeActionResult CaptureTurnStepBefore(RuntimeRun& run);
RuntimeActionResult CaptureTurnStepContinuesAfter(RuntimeRun& run, int fromPhase, int toPhase);
RuntimeActionResult CaptureTurnStepBlockedAfter(RuntimeRun& run, int phase, const char* blockKind,
                                                const char* uiGate);
