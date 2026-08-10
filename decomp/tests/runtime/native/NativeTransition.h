#ifndef IMPERIALISM_NATIVE_TRANSITION_H
#define IMPERIALISM_NATIVE_TRANSITION_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error NativeTransition is test-only and must not be included in the production build
#endif

#include "screens/RuntimeActionResult.h"

#include "parson.h"

class RuntimeRun;

// Owns before/case/result/after capture for one synchronous native model transition.
// Case functions prepare state, describe arguments, and invoke a production method only.
class NativeTransition {
public:
  explicit NativeTransition(RuntimeRun& run);

  // Captures prepared game state as "before" and takes ownership of caseCapture as "case".
  RuntimeActionResult Begin(JSON_Value* caseCapture);

  // Captures result and "after" game state. Overloads cover void, bool, integer, and JSON
  // results. Finish(JSON_Value*) takes ownership of result.
  RuntimeActionResult Finish();
  RuntimeActionResult Finish(bool result);
  RuntimeActionResult Finish(int result);
  RuntimeActionResult Finish(JSON_Value* result);

  RuntimeRun& Run() const;

private:
  RuntimeActionResult CaptureResult(JSON_Value* resultValue);

  RuntimeRun& run_;
};

#endif
