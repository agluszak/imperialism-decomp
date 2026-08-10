#include "RuntimeDifferentialCapture.h"

#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "JsonObject.h"

RuntimeDifferentialCapture::RuntimeDifferentialCapture(RuntimeRun& run) : run_(run) {}

RuntimeActionResult RuntimeDifferentialCapture::Begin(JSON_Value* caseValue) {
  if (!CaptureGameState(run_, "before")) {
    JsonFreeValue(caseValue);
    return RuntimeActionResult::Failure("could not capture differential before-state");
  }

  run_.SetCapture("case", caseValue);
  if (!run_.HasCapture("case")) {
    return RuntimeActionResult::Failure("could not capture differential case");
  }

  return RuntimeActionResult::Success();
}

RuntimeActionResult RuntimeDifferentialCapture::Finish() {
  run_.SetCapture("result", json_value_init_null());
  if (!run_.HasCapture("result")) {
    return RuntimeActionResult::Failure("could not capture differential void result");
  }
  return CaptureAfter();
}

RuntimeActionResult RuntimeDifferentialCapture::Finish(bool result) {
  run_.SetCapture("result", json_value_init_boolean(result ? 1 : 0));
  if (!run_.HasCapture("result")) {
    return RuntimeActionResult::Failure("could not capture differential boolean result");
  }
  return CaptureAfter();
}

RuntimeActionResult RuntimeDifferentialCapture::Finish(int result) {
  run_.SetCapture("result", json_value_init_number(result));
  if (!run_.HasCapture("result")) {
    return RuntimeActionResult::Failure("could not capture differential integer result");
  }
  return CaptureAfter();
}

RuntimeActionResult RuntimeDifferentialCapture::CaptureAfter() {
  if (!CaptureGameState(run_, "after")) {
    return RuntimeActionResult::Failure("could not capture differential after-state");
  }
  return RuntimeActionResult::Success();
}
