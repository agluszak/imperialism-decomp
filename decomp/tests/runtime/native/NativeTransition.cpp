#include "NativeTransition.h"

#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

NativeTransition::NativeTransition(RuntimeRun& run) : run_(run) {}

RuntimeActionResult NativeTransition::Begin(JSON_Value* caseCapture) {
  if (caseCapture == 0) {
    return RuntimeActionResult::Failure("the transition case capture is unavailable");
  }
  if (!CaptureGameState(run_, "before")) {
    json_value_free(caseCapture);
    return RuntimeActionResult::Failure("the before game-state capture is unavailable");
  }
  run_.SetCapture("case", caseCapture);
  if (!run_.HasCapture("case")) {
    return RuntimeActionResult::Failure("the transition case capture is unavailable");
  }
  return RuntimeActionResult::Success();
}

RuntimeActionResult NativeTransition::Finish() {
  return CaptureResult(json_value_init_null());
}

RuntimeActionResult NativeTransition::Finish(bool result) {
  return CaptureResult(json_value_init_boolean(result ? 1 : 0));
}

RuntimeActionResult NativeTransition::Finish(int result) {
  return CaptureResult(json_value_init_number(result));
}

RuntimeActionResult NativeTransition::Finish(JSON_Value* result) {
  return CaptureResult(result);
}

RuntimeRun& NativeTransition::Run() const {
  return run_;
}

RuntimeActionResult NativeTransition::CaptureResult(JSON_Value* resultValue) {
  if (resultValue == 0) {
    return RuntimeActionResult::Failure("the transition result capture is unavailable");
  }
  run_.SetCapture("result", resultValue);
  if (!run_.HasCapture("result")) {
    return RuntimeActionResult::Failure("the transition result capture is unavailable");
  }
  if (!CaptureGameState(run_, "after")) {
    return RuntimeActionResult::Failure("the after game-state capture is unavailable");
  }
  return RuntimeActionResult::Success();
}
