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
// Runtime-only overlay for save-backed differentials: turn, unit_ids, rng, news,
// and pending. The caller owns the value on success.
bool BuildRuntimeEphemeralState(const RuntimeRun& run, JSON_Value** state);
// Snapshot the live game into a named capture (for example "before" / "after").
bool CaptureGameState(RuntimeRun& run, const char* name);
// Save-backed before/after transport: writes save/rt_native_<name>.imp and publishes
// {save, ephemeral} where ephemeral holds non-persisted GameState fields.
bool CaptureSaveBackedGameState(RuntimeRun& run, const char* name);
void CaptureRuntimeGameState(RuntimeRun& run);

#endif
