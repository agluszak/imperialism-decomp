#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeActionResult is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

// The outcome of one screen action, carrying its own diagnosis.
//
// The existing screen drivers return a bare `bool`. RuntimeUiDriver::RequireControl builds a
// rich multi-line explanation of *why* a control did not resolve -- wrong root, ambiguous tag
// path, wrong class, not actionable, wrong event number -- and StrategicMapDriver throws all
// of it away, so every call site writes another failure branch with prose that is vaguer than
// what was discarded ("end-turn control is missing").
//
// An action returns this instead, so RT_ACTION can propagate the real diagnosis and the call
// site does not need a failure branch at all.
class RuntimeActionResult {
public:
  RuntimeActionResult() : succeeded(true) {}

  static RuntimeActionResult Success() {
    return RuntimeActionResult();
  }

  static RuntimeActionResult Failure(const CString& message) {
    RuntimeActionResult result;
    result.succeeded = false;
    result.failureMessage = message;
    return result;
  }

  static RuntimeActionResult Failure(const char* message) {
    return Failure(CString(message != 0 ? message : ""));
  }

  // Success when `condition` holds, otherwise a failure carrying `message`. For the common
  // driver shape "check one thing, explain it if it is wrong".
  static RuntimeActionResult Require(bool condition, const CString& message) {
    return condition ? Success() : Failure(message);
  }

  bool Succeeded() const {
    return succeeded;
  }

  const CString& FailureMessage() const {
    return failureMessage;
  }

private:
  bool succeeded;
  CString failureMessage;
};
