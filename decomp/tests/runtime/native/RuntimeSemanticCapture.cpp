#include "RuntimeSemanticCapture.h"

#include "RuntimeRun.h"

bool CaptureVoidOpResult(RuntimeRun& run) {
  run.SetCapture("result", json_value_init_null());
  return run.HasCapture("result");
}

bool CaptureBooleanOpResult(RuntimeRun& run, bool result) {
  run.SetCapture("result", json_value_init_boolean(result ? 1 : 0));
  return run.HasCapture("result");
}

bool CaptureIntegerOpResult(RuntimeRun& run, int result) {
  run.SetCapture("result", json_value_init_number(result));
  return run.HasCapture("result");
}
