#ifndef IMPERIALISM_RUNTIME_SEMANTIC_CAPTURE_H
#define IMPERIALISM_RUNTIME_SEMANTIC_CAPTURE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeSemanticCapture is test-only and must not be included in the production build
#endif

#include "parson.h"

class RuntimeRun;

// Capture an operation's native semantic return under `result`.
bool CaptureVoidOpResult(RuntimeRun& run);
bool CaptureBooleanOpResult(RuntimeRun& run, bool result);
bool CaptureIntegerOpResult(RuntimeRun& run, int result);

#endif
