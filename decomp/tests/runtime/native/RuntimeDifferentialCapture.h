#ifndef IMPERIALISM_RUNTIME_DIFFERENTIAL_CAPTURE_H
#define IMPERIALISM_RUNTIME_DIFFERENTIAL_CAPTURE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeDifferentialCapture is test-only and must not be included in the production build
#endif

#include "screens/RuntimeActionResult.h"

#include "parson.h"

class RuntimeRun;

// Shared before/case/result/after capture sequence for Rust differential scenarios.
class RuntimeDifferentialCapture {
public:
  explicit RuntimeDifferentialCapture(RuntimeRun& run);

  RuntimeActionResult Begin(JSON_Value* caseValue);
  RuntimeActionResult Finish();
  RuntimeActionResult Finish(bool result);
  RuntimeActionResult Finish(int result);

private:
  RuntimeActionResult CaptureAfter();

  RuntimeRun& run_;
};

#endif
