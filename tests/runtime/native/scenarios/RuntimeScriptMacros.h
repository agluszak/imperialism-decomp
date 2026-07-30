#pragma once

#ifndef IMPERIALISM_RUNTIME_SCRIPT_MACROS_H
#define IMPERIALISM_RUNTIME_SCRIPT_MACROS_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeScriptMacros is test-only and must not be included in the production build
#endif

// Linear script vocabulary for RuntimeScriptScenario::Script().
//
// A scenario is driven by re-entry: RuntimeScenario::AdvanceScenario() is called again on
// each admitted observation and yields by returning. Written by hand that forces every test
// into a private `enum Phase`, a dispatcher, one method per phase, and a set of "did I
// already do this?" booleans -- 369 lines to express what is really eight actions and six
// assertions.
//
// These macros hide a protothread instead: a saved program counter plus Duff's-device
// `case` labels, so the author writes actions, waits and assertions in order and the yields
// happen inside the macros. MSVC 5.0 is the compiler, so this is the mechanism available --
// no coroutines, no lambdas, no variadic macros -- and it is one of the few places where
// macros beat explicit C++.
//
// Everything here was validated against the real compiler by `just protothread-probe --run`,
// which compiles each hazard as its own translation unit with the harness flags and then
// links and runs a protothread to check its resume order. Change a macro and re-run it.
//
// ---------------------------------------------------------------------------------------
// THE ONE RULE: state that must survive a yield is a member field, never a local.
// ---------------------------------------------------------------------------------------
//
// The compiler enforces this. MSVC rejects any *initialized* local whose scope spans a case
// label:
//
//     C2360: initialization of 'value' is skipped by 'case' label
//
// so `TView* view = CurrentMainView();` at Script() statement level is a compile error, and
// so is a `for (int i = 0; ...)` induction variable. That is a feature: those are exactly
// the variables that would silently reset on every resume. Wrap a local in a brace block
// containing no RT_ macro and it compiles fine, including non-POD types under /GX:
//
//     {
//       TGreatPower* player = ActivePlayer();   // scope ends before the next yield
//       RT_REQUIRE_NOT_NULL(player);
//     }
//
// Loops around yields are fine as long as the counter is a field:
//
//     while (toggleCycles < 2) {
//       RT_ACTION("zoom out", StrategicMap().ZoomOut());
//       ++toggleCycles;
//     }
//
// Two hazards the compiler does NOT catch:
//
//   * An *uninitialized* POD local spanning a case label is accepted. `int value;` compiles
//     and its value does not survive the yield. Do not do this.
//   * A `case` label inside a `try` block is accepted, and resuming there skips the try's
//     EH state setup: the probe's catch never fires and the CRT aborts with "abnormal
//     program termination". Never put an RT_ macro inside try/catch.
//
// ---------------------------------------------------------------------------------------
// Program-counter slots
// ---------------------------------------------------------------------------------------
//
// Each yield point needs a `case` value unique within Script(). __LINE__ supplies that, and
// two RT_ macros on one source line collide as C2196 "case value already used" -- a compile
// error rather than a wrong resume. One macro per line.
//
// The combinators at the bottom expand to two yield points on a single line, so they cannot
// both use __LINE__. Each macro therefore takes an explicit slot, and a combinator gives its
// second yield the negated line. Program counters are only ever compared for equality and 0
// is the start sentinel, so the negative half of the range is free and cannot collide with
// any positive slot.

#include "RuntimeScriptStatus.h"

#define RT_SLOT_PRIMARY __LINE__
#define RT_SLOT_SECONDARY (-(__LINE__))

// Opens the script. Every RT_ macro must sit between RT_BEGIN and RT_END.
#define RT_BEGIN()                                                                                 \
  switch (ScriptProgramCounter()) {                                                                \
  case 0:

// Closes the script. Catches both a corrupt program counter (`default:`) and a script that
// returned without RT_PASS/RT_FAIL, which would otherwise be an undetectable stall.
#define RT_END()                                                                                   \
  default:                                                                                         \
    break;                                                                                         \
    }                                                                                              \
    FailScript("script returned without RT_PASS()", __FILE__, __LINE__)

#define RT_AWAIT_AT(slot, condition, observations)                                                 \
  do {                                                                                             \
    SetScriptProgramCounter(slot);                                                                 \
  case slot:                                                                                       \
    if (!(condition)) {                                                                            \
      AwaitScript((observations), #condition, __FILE__, __LINE__);                                 \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define RT_AWAIT_SCREEN_AT(slot, ViewClass, eventCode)                                             \
  do {                                                                                             \
    SetScriptProgramCounter(slot);                                                                 \
  case slot:                                                                                       \
    if (!ScreenIsCurrent(RUNTIME_CLASS(ViewClass), (eventCode))) {                                 \
      AwaitScreenScript(RUNTIME_CLASS(ViewClass), (eventCode), #ViewClass, __FILE__, __LINE__);    \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define RT_ACTION_AT(slot, label, action)                                                          \
  do {                                                                                             \
    if (!RunScriptAction((label), (action), __FILE__, __LINE__))                                   \
      return;                                                                                      \
    SetScriptProgramCounter(slot);                                                                 \
    ContinueAfterAction();                                                                         \
    return;                                                                                        \
  case slot:;                                                                                      \
  } while (0)

// Perform one action and carry on *without* yielding. For a step whose effect is synchronous --
// a model call the game does not need a turn to process. RT_ACTION is for anything that has to
// reach the game through its message loop.
//
// Choosing wrong in this direction stalls: a scenario that pokes the model and then waits for
// the application to go idle can wait forever, because a map left invalidating never reports an
// idle with lCount == 0. Choosing wrong in the other direction reads a control's state before
// the game has updated it.
//
// No program-counter slot, so this is not a yield point and several may share a line.
#define RT_STEP(label, action)                                                                     \
  do {                                                                                             \
    if (!RunScriptAction((label), (action), __FILE__, __LINE__))                                   \
      return;                                                                                      \
  } while (0)

#define RT_YIELD_AT(slot)                                                                          \
  do {                                                                                             \
    SetScriptProgramCounter(slot);                                                                 \
    ContinueAfterAction();                                                                         \
    return;                                                                                        \
  case slot:;                                                                                      \
  } while (0)

// Hand control back to the game once, then carry on. For a step that changes state through a
// direct model call rather than a control activation, where there is no RuntimeActionResult to
// report. Prefer RT_ACTION when there is one.
//
// A loop that handles a step and then re-tests its condition MUST yield on every path, or it
// spins: "some expected screen is showing" is not the same predicate as "progress was made",
// and conflating them is how a script busy-loops inside Script() with the game unable to
// advance. Yield after handling, and await only when nothing was handled.
#define RT_YIELD() RT_YIELD_AT(RT_SLOT_PRIMARY)

// Wait until `condition` holds, re-checking on each of `observations`. The stringised
// condition and this source location are published in the heartbeat and the result file, so
// a stall says what it was waiting for.
#define RT_AWAIT(condition, observations) RT_AWAIT_AT(RT_SLOT_PRIMARY, condition, observations)

// Wait until `ViewClass` is the current main view at `eventCode`, with no modal covering it.
// The idle-screen predicate 22 scenarios spell out by hand.
#define RT_AWAIT_SCREEN(ViewClass, eventCode)                                                      \
  RT_AWAIT_SCREEN_AT(RT_SLOT_PRIMARY, ViewClass, eventCode)

// Perform one action, then yield once so the game can process it. `action` is a
// RuntimeActionResult, so a screen driver's diagnostic becomes the scenario's failure
// instead of being replaced by hand-written prose at the call site.
#define RT_ACTION(label, action) RT_ACTION_AT(RT_SLOT_PRIMARY, label, action)

// Drive a reusable RuntimeScriptFragment to completion, re-entering it on each observation.
// The fragment arms its own waits, so this yields without arming anything itself.
#define RT_RUN(fragmentCall)                                                                       \
  do {                                                                                             \
    SetScriptProgramCounter(RT_SLOT_PRIMARY);                                                      \
  case RT_SLOT_PRIMARY: {                                                                          \
    RuntimeScriptStatus rtStatus = (fragmentCall);                                                 \
    if (rtStatus != kRuntimeScriptComplete)                                                        \
      return;                                                                                      \
  }                                                                                                \
  } while (0)

// End the run here, with this screen painted, when the host asked to be held at it for
// inspection (`--hold NAME`). A no-op on a normal run. Not a yield point: it either finishes the
// script or does nothing at all.
#define RT_HOLD_SCREEN(screenName)                                                                 \
  do {                                                                                             \
    if (HoldScriptAtScreen(screenName)) {                                                          \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define RT_PASS()                                                                                  \
  do {                                                                                             \
    PassScript();                                                                                  \
    return;                                                                                        \
  } while (0)

#define RT_FAIL(text)                                                                              \
  do {                                                                                             \
    FailScript((text), __FILE__, __LINE__);                                                        \
    return;                                                                                        \
  } while (0)

// Fatal assertions. The failure text is built for you: the stringised expression, the two
// values where there are two, and a context block naming the source location, phase, current
// turn event, current view class, modal depth and any armed wait.
#define RT_REQUIRE(expr)                                                                           \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      FailRequirement(#expr, __FILE__, __LINE__);                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

// Each operand appears exactly once below. Writing it twice -- once compared, once formatted
// -- meant a stateful accessor reported values other than the ones that failed.
#define RT_REQUIRE_EQ(expected, actual)                                                            \
  do {                                                                                             \
    CString rtExpectedText;                                                                        \
    CString rtActualText;                                                                          \
    if (!RuntimeCompareEqual((expected), (actual), &rtExpectedText, &rtActualText)) {              \
      FailRequirementRelation(#actual " == " #expected, "==", rtExpectedText, rtActualText,        \
                              __FILE__, __LINE__);                                                 \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define RT_REQUIRE_NE(expected, actual)                                                            \
  do {                                                                                             \
    CString rtExpectedText;                                                                        \
    CString rtActualText;                                                                          \
    if (!RuntimeCompareUnequal((expected), (actual), &rtExpectedText, &rtActualText)) {            \
      FailRequirementRelation(#actual " != " #expected, "!=", rtExpectedText, rtActualText,        \
                              __FILE__, __LINE__);                                                 \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define RT_REQUIRE_NOT_NULL(pointer)                                                               \
  do {                                                                                             \
    if ((pointer) == 0) {                                                                          \
      FailRequirement(#pointer " != 0", __FILE__, __LINE__);                                       \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define RT_REQUIRE_KIND_OF(view, Type)                                                             \
  do {                                                                                             \
    TView* rtView = (view);                                                                        \
    if (!RuntimeIsViewKindOf(rtView, RUNTIME_CLASS(Type))) {                                       \
      FailRequirementKindOf(#view, #Type, rtView, __FILE__, __LINE__);                             \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

// Non-fatal: records the failure and carries on, so one run can report several problems. The
// scenario still fails at RT_PASS if any check failed.
#define RT_CHECK(expr)                                                                             \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      RecordCheckFailure(#expr, __FILE__, __LINE__);                                               \
    }                                                                                              \
  } while (0)

// --------------------------------------------------------------------------------------
// Combinators for the shapes that repeat. Deliberately a small closed set: these exist to
// remove duplication that already exists, not to grow into a language. Each uses the
// secondary slot for its second yield so both fit on one source line.
// --------------------------------------------------------------------------------------

// Activate something, then wait for a different screen to come up.
#define RT_OPEN_SCREEN(label, action, ViewClass, eventCode)                                        \
  RT_ACTION_AT(RT_SLOT_PRIMARY, label, action);                                                    \
  RT_AWAIT_SCREEN_AT(RT_SLOT_SECONDARY, ViewClass, eventCode)

// Leave a screen back to the strategic map: the most repeated transition in the suite.
// Requires the including TU to see TMapUberPicture and turn_event_codes.h.
#define RT_CLOSE_TO_MAP(label, action)                                                             \
  RT_ACTION_AT(RT_SLOT_PRIMARY, label, action);                                                    \
  RT_AWAIT_SCREEN_AT(RT_SLOT_SECONDARY, TMapUberPicture, kTurnEventStrategicMap)

// Activate something and wait for its effect on the same screen.
#define RT_ACTIVATE_AND_AWAIT(label, action, condition, observations)                              \
  RT_ACTION_AT(RT_SLOT_PRIMARY, label, action);                                                    \
  RT_AWAIT_AT(RT_SLOT_SECONDARY, condition, observations)

// --------------------------------------------------------------------------------------
// Fragment vocabulary. Same protothread, but a fragment yields a RuntimeScriptStatus so its
// caller knows whether to yield too. Use these inside a RuntimeScriptFragment method; use the
// RT_ forms above inside a Script().
// --------------------------------------------------------------------------------------

#define RT_FRAGMENT_BEGIN()                                                                        \
  switch (FragmentProgramCounter()) {                                                              \
  case 0:

// Reaching the end without RT_FRAGMENT_DONE means the sequence has no terminating path, which
// would otherwise stall the caller with no explanation.
#define RT_FRAGMENT_END()                                                                          \
  default:                                                                                         \
    break;                                                                                         \
    }                                                                                              \
    FailFragment("script fragment returned without completing", __FILE__, __LINE__);               \
    return kRuntimeScriptFailed

#define RT_FRAGMENT_AWAIT_AT(slot, condition, observations)                                        \
  do {                                                                                             \
    SetFragmentProgramCounter(slot);                                                               \
  case slot:                                                                                       \
    if (!(condition)) {                                                                            \
      AwaitFragment((observations), #condition, __FILE__, __LINE__);                               \
      return kRuntimeScriptRunning;                                                                \
    }                                                                                              \
  } while (0)

#define RT_FRAGMENT_AWAIT(condition, observations)                                                 \
  RT_FRAGMENT_AWAIT_AT(RT_SLOT_PRIMARY, condition, observations)

#define RT_FRAGMENT_AWAIT_SCREEN_AT(slot, ViewClass, eventCode)                                    \
  do {                                                                                             \
    SetFragmentProgramCounter(slot);                                                               \
  case slot:                                                                                       \
    if (!ScreenIsCurrentForFragment(RUNTIME_CLASS(ViewClass), (eventCode))) {                      \
      AwaitScreenFragment(RUNTIME_CLASS(ViewClass), (eventCode), #ViewClass, __FILE__, __LINE__);  \
      return kRuntimeScriptRunning;                                                                \
    }                                                                                              \
  } while (0)

#define RT_FRAGMENT_AWAIT_SCREEN(ViewClass, eventCode)                                             \
  RT_FRAGMENT_AWAIT_SCREEN_AT(RT_SLOT_PRIMARY, ViewClass, eventCode)

#define RT_FRAGMENT_ACTION_AT(slot, label, action)                                                 \
  do {                                                                                             \
    if (!RunFragmentAction((label), (action), __FILE__, __LINE__))                                 \
      return kRuntimeScriptFailed;                                                                 \
    SetFragmentProgramCounter(slot);                                                               \
    ContinueFragmentAfterAction();                                                                 \
    return kRuntimeScriptRunning;                                                                  \
  case slot:;                                                                                      \
  } while (0)

#define RT_FRAGMENT_ACTION(label, action) RT_FRAGMENT_ACTION_AT(RT_SLOT_PRIMARY, label, action)

// Hand control back once. Same rule as RT_YIELD: a loop that handles a step must yield on
// every path, or it spins while the game never gets to act on what was just done.
#define RT_FRAGMENT_YIELD()                                                                        \
  do {                                                                                             \
    SetFragmentProgramCounter(RT_SLOT_PRIMARY);                                                    \
    ContinueFragmentAfterAction();                                                                 \
    return kRuntimeScriptRunning;                                                                  \
  case RT_SLOT_PRIMARY:;                                                                           \
  } while (0)

#define RT_FRAGMENT_STEP(label, action)                                                            \
  do {                                                                                             \
    if (!RunFragmentAction((label), (action), __FILE__, __LINE__))                                 \
      return kRuntimeScriptFailed;                                                                 \
  } while (0)

#define RT_FRAGMENT_REQUIRE(expr)                                                                  \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      FailFragmentRequirement(#expr, __FILE__, __LINE__);                                          \
      return kRuntimeScriptFailed;                                                                 \
    }                                                                                              \
  } while (0)

#define RT_FRAGMENT_FAIL(text)                                                                     \
  do {                                                                                             \
    FailFragment((text), __FILE__, __LINE__);                                                      \
    return kRuntimeScriptFailed;                                                                   \
  } while (0)

// The sequence finished; the calling script continues with its next statement.
#define RT_FRAGMENT_DONE()                                                                         \
  do {                                                                                             \
    return kRuntimeScriptComplete;                                                                 \
  } while (0)

#endif
