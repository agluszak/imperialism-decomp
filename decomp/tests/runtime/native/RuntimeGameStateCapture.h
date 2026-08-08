#ifndef IMPERIALISM_RUNTIME_GAME_STATE_CAPTURE_H
#define IMPERIALISM_RUNTIME_GAME_STATE_CAPTURE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeGameStateCapture is test-only and must not be included in the production build
#endif

#include "parson.h"

class RuntimeRun;

// Builds the same semantic object deserialized by imperialism_core::GameState.
// The caller owns the returned JSON value on success.
bool BuildRuntimeGameState(const RuntimeRun& run, JSON_Value** state);
void CaptureRuntimeGameState(RuntimeRun& run);

#endif
