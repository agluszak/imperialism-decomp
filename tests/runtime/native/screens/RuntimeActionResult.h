#pragma once

#ifndef IMPERIALISM_RUNTIME_ACTION_RESULT_H
#define IMPERIALISM_RUNTIME_ACTION_RESULT_H

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
// Whether the game needs a turn through its message loop before the effect of an action is
// observable.
//
// This used to live in the author's head, as the choice between RT_ACTION (yield) and RT_STEP
// (do not). Choosing wrong stalls forever in one direction -- a script that pokes the model and
// then waits for application idle can wait for an idle that never comes -- and reads stale state
// in the other. The action is what knows; the script is what was being asked.
enum RuntimeActionCompletion {
  // The effect is already visible: a model call, a field write, a direct draw.
  kActionImmediate,
  // The action reached the game through its message loop, so the script must let the game run
  // before it looks at the result.
  kActionAfterMessageBarrier
};

class RuntimeActionResult {
public:
  RuntimeActionResult() : succeeded(true), completion(kActionImmediate) {}

  static RuntimeActionResult Success() {
    return RuntimeActionResult();
  }

  // Succeeded, and the game has to run before the effect can be observed. Control activations
  // are the archetype: the click is delivered as a message, not as a call.
  static RuntimeActionResult SuccessAfterMessageBarrier() {
    RuntimeActionResult result;
    result.completion = kActionAfterMessageBarrier;
    return result;
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

  RuntimeActionCompletion Completion() const {
    return completion;
  }

  bool NeedsMessageBarrier() const {
    return completion == kActionAfterMessageBarrier;
  }

  // Carry an existing result through a wrapper while upgrading it to a barrier -- for a driver
  // that composes a model call and an activation and must report the stronger of the two.
  RuntimeActionResult AfterMessageBarrier() const {
    RuntimeActionResult result(*this);
    result.completion = kActionAfterMessageBarrier;
    return result;
  }

  const CString& FailureMessage() const {
    return failureMessage;
  }

private:
  bool succeeded;
  CString failureMessage;
  RuntimeActionCompletion completion;
};

#endif
