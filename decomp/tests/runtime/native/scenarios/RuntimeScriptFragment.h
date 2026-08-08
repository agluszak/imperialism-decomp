#pragma once

#ifndef IMPERIALISM_RUNTIME_SCRIPT_FRAGMENT_H
#define IMPERIALISM_RUNTIME_SCRIPT_FRAGMENT_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeScriptFragment is test-only and must not be included in the production build
#endif

#include "RuntimeScriptScenario.h"
#include "RuntimeScriptStatus.h"
#include "screens/RuntimeActionResult.h"

class TView;

// A reusable piece of a linear script.
//
// Some sequences belong to several tests: ending a turn walks the Deal Book, the newspaper,
// warning modals, turn alerts and a possible re-submission, and four scenarios each grew their
// own version of it, diverging on which safety checks they kept. A fragment lets one
// implementation be driven from any script with RT_RUN.
//
// It is the same protothread as a Script(), with one difference: it cannot yield by returning
// void, because the caller has to know whether to yield too. Its steps therefore use the
// RT_FRAGMENT_* macros, which return a RuntimeScriptStatus.
//
// Write a fragment with those macros rather than by hand. Hand-rolling puts the
// program-counter store and its `case` label on two different source lines, so they never
// match and the fragment silently never advances -- inside a macro every __LINE__ collapses to
// the invocation line, which is the whole trick.
class RuntimeScriptFragment {
public:
  virtual ~RuntimeScriptFragment() {}

protected:
  RuntimeScriptFragment();

  // Bind the fragment to its scenario and rewind it. A fragment is a member of a
  // (file-static, never reconstructed) scenario, so a second run of the same sequence in one
  // scenario must call this again or it resumes where the first left off.
  void BeginFragment(RuntimeScriptScenario& scenario);
  bool IsBound() const;

  // --- Support surface the RT_FRAGMENT_ macros call. Not for direct use. ---
  int FragmentProgramCounter() const;
  void SetFragmentProgramCounter(int slot);
  void AwaitFragment(unsigned int observationKinds, const char* expression, const char* file,
                     int line);
  bool ScreenIsCurrentForFragment(CRuntimeClass* viewClass, int eventCode) const;
  void AwaitScreenFragment(CRuntimeClass* viewClass, int eventCode, const char* className,
                           const char* file, int line);
  bool RunFragmentAction(const char* label, const RuntimeActionResult& result, const char* file,
                         int line);
  void FailFragment(const char* text, const char* file, int line);
  void FailFragmentRequirement(const char* expression, const char* file, int line);
  int CurrentTurnEventForFragment() const;

  // Forwarders onto the scenario's protected surface. Friendship is not inherited, so a
  // concrete fragment cannot reach RuntimeScenario's protected members through Host() even
  // though this class can -- these exist so it does not have to.
  void ContinueFragmentAfterAction();
  void RecordHandledModalForFragment(const char* label);
  void RecordUnexpectedModalForFragment(TView* modal);
  bool AdvanceNewspaperForFragment();
  void ResetNewspaperAdvanceForFragment();

  // The scenario driving this fragment, for steps that need its public helpers.
  RuntimeScriptScenario& Host() const;

private:
  RuntimeScriptScenario* host;
  int fragmentProgramCounter;
};

#endif
