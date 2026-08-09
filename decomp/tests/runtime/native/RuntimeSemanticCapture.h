#ifndef IMPERIALISM_RUNTIME_SEMANTIC_CAPTURE_H
#define IMPERIALISM_RUNTIME_SEMANTIC_CAPTURE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeSemanticCapture is test-only and must not be included in the production build
#endif

#include "parson.h"

class RuntimeRun;

// Captures the semantic GameState object under `name` (before/after/game_state).
bool CaptureNamedGameState(RuntimeRun& run, const char* name);

// Operation outcome JSON shared with imperialism-testkit DiffOpResult.
JSON_Value* BuildAcceptedOpResult();
JSON_Value* BuildRejectedNotMajorOpResult(int nationSlot);

#endif
