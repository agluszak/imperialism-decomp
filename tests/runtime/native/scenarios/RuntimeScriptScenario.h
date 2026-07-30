#pragma once

#ifndef IMPERIALISM_RUNTIME_SCRIPT_SCENARIO_H
#define IMPERIALISM_RUNTIME_SCRIPT_SCENARIO_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeScriptScenario is test-only and must not be included in the production build
#endif

#include "RuntimeAssertionText.h"
#include "RuntimeScenario.h"
#include "RuntimeScriptStatus.h"
#include "screens/RuntimeActionResult.h"

struct CRuntimeClass;

// A scenario written as a linear script instead of a phase machine.
//
// RuntimeScenario re-enters AdvanceScenario() on each admitted observation, which forces a
// hand-written test to carry a phase enum, a dispatcher, one method per phase, and ad-hoc
// "did I already do this?" flags. A subclass here overrides Script() and nothing else,
// writing actions, waits and assertions in order; the RT_ macros in RuntimeScriptMacros.h
// hide the program counter and the yields.
//
// Coexists with the phase-machine scenarios: it only overrides AdvanceScenario, so nothing
// about the existing base changes for tests that have not migrated.
class RuntimeScriptScenario : public RuntimeScenario {
public:
  void AdvanceScenario() override;

protected:
  RuntimeScriptScenario();

  // The author's linear body. Must start with RT_BEGIN() and end with RT_END().
  virtual void Script();

  // Called by a start-point base once its checkpoint is reached: resets the program counter
  // and hands the first observation to Script().
  void BeginScript(const char* phaseName);

  // The turn event the game is currently showing, for scripts that branch on a sequence of
  // screens. A script must not read g_pViewMgr itself.
  int CurrentTurnEvent() const;

  // --- Support surface the RT_ macros call. Not for direct use in a Script(). ---
  int ScriptProgramCounter() const;
  void SetScriptProgramCounter(int slot);
  void AwaitScript(unsigned int observationKinds, const char* expression, const char* file,
                   int line);
  bool ScreenIsCurrent(CRuntimeClass* viewClass, int eventCode) const;
  void AwaitScreenScript(CRuntimeClass* viewClass, int eventCode, const char* className,
                         const char* file, int line);
  bool RunScriptAction(const char* label, const RuntimeActionResult& result, const char* file,
                       int line);
  void PassScript();
  void FailScript(const char* text, const char* file, int line);
  void FailRequirement(const char* expression, const char* file, int line);
  void FailRequirementRelation(const char* expression, const char* relation,
                               const CString& expected, const CString& actual, const char* file,
                               int line);
  void FailRequirementKindOf(const char* expression, const char* typeName, TView* view,
                             const char* file, int line);
  void RecordCheckFailure(const char* expression, const char* file, int line);

private:
  // The saved yield point. 0 means "start from the top"; RT_ macros store __LINE__ or its
  // negation (see RuntimeScriptMacros.h on slots).
  int scriptProgramCounter;
  // Set while Script() is running, so the no-arm deadlock check below can tell a script that
  // yielded properly from one that fell through without arming anything.
  bool scriptArmedOrFinished;
  int checkFailures;

  // A fragment drives the same protothread surface from outside the class hierarchy.
  friend class RuntimeScriptFragment;
};

#endif
