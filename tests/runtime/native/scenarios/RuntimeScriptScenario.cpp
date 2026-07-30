#include "RuntimeScriptScenario.h"

#include "RuntimeObservation.h"
#include "RuntimeObservations.h"
#include "RuntimeRun.h"

#include "game/core/global_data_tables.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/view_registries.h"

RuntimeScriptScenario::RuntimeScriptScenario()
    : scriptProgramCounter(0), scriptArmedOrFinished(false), checkFailures(0) {}

void RuntimeScriptScenario::Script() {
  FailScenarioText("scenario derives from RuntimeScriptScenario but does not override Script()");
}

void RuntimeScriptScenario::AdvanceScenario() {
  scriptArmedOrFinished = false;
  Script();
  if (RunState().IsFinished()) {
    return;
  }
  // AdvanceDriver zeroes the awaited-observation mask before every entry, so a script that
  // returns without arming a wait is never woken again -- previously an invisible hang that
  // the host could only report as `heartbeat_stopped`. Name it instead.
  if (!scriptArmedOrFinished && !RunState().AwaitState().IsArmed()) {
    FailScenarioText("script returned without awaiting anything, passing or failing; the "
                     "scenario would never be woken again");
  }
}

void RuntimeScriptScenario::BeginScript(const char* phaseName) {
  scriptProgramCounter = 0;
  checkFailures = 0;
  EnterScenarioStep(phaseName, "begin_script");
  ContinueAfterAction();
  scriptArmedOrFinished = true;
}

void RuntimeScriptScenario::MarkScriptStep(const char* label) {
  EnterScenarioStep(RuntimeAssertionText::PhaseSlug(label), label);
}

int RuntimeScriptScenario::CurrentTurnEvent() const {
  return g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1;
}

bool RuntimeScriptScenario::HoldScriptAtScreen(const char* screenName) {
  if (!HoldAtScenarioScreen(screenName)) {
    return false;
  }
  // The run is about to end with the screen still up, so it has to be painted: a scenario that
  // only ever activated controls may never have let one frame reach the window.
  TView* view = CurrentMainView();
  if (view != 0 && view->nativeWindow50 != 0 && view->nativeWindow50->m_hWnd != 0) {
    RedrawWindow(view->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
  }
  PassScript();
  return true;
}

int RuntimeScriptScenario::ScriptProgramCounter() const {
  return scriptProgramCounter;
}

void RuntimeScriptScenario::SetScriptProgramCounter(int slot) {
  scriptProgramCounter = slot;
}

void RuntimeScriptScenario::AwaitScript(unsigned int observationKinds, const char* expression,
                                        const char* file, int line) {
  AwaitAt(observationKinds, expression, file, line);
  scriptArmedOrFinished = true;
}

bool RuntimeScriptScenario::ScreenIsCurrent(CRuntimeClass* viewClass, int eventCode) const {
  // The idle-screen predicate 22 scenarios spell out by hand: right event, right main-view
  // class, and nothing modal on top of it. Omitting the modal check is what let a stray
  // dialog be mistaken for the screen underneath.
  if (g_pViewMgr == 0 || g_pViewMgr->currentTurnEventCode != eventCode) {
    return false;
  }
  if (!g_ModalViewStack.IsEmpty()) {
    return false;
  }
  return RuntimeIsViewKindOf(CurrentMainView(), viewClass);
}

void RuntimeScriptScenario::AwaitScreenScript(CRuntimeClass* viewClass, int eventCode,
                                              const char* className, const char* file, int line) {
  (void)viewClass;
  CString expression;
  expression.Format("%s to be the current screen at event 0x%04x with no modal above it", className,
                    static_cast<unsigned int>(eventCode));
  // A screen transition can be signalled by any of a UI rebuild, a paint, a turn event or a
  // modal unwinding, so waiting on one of them alone stalls on the others.
  AwaitScript(kObserveUiStateChanged, static_cast<LPCSTR>(expression), file, line);
}

bool RuntimeScriptScenario::RunScriptAction(const char* label, const RuntimeActionResult& result,
                                            const char* file, int line) {
  RunState().EnterPhase(RuntimeAssertionText::PhaseSlug(label), label);
  if (result.Succeeded()) {
    return true;
  }
  // The driver already explained precisely what went wrong; say that rather than replacing
  // it with prose from the call site.
  CString text;
  text.Format("action \"%s\" failed: %s", label, static_cast<LPCSTR>(result.FailureMessage()));
  FailScript(static_cast<LPCSTR>(text), file, line);
  return false;
}

void RuntimeScriptScenario::PassScript() {
  scriptArmedOrFinished = true;
  if (checkFailures != 0) {
    // RT_CHECK failures are non-fatal individually but must not let the run report success.
    CString text;
    text.Format("%d non-fatal check(s) failed; the first is recorded as the assertion",
                checkFailures);
    FailScenarioText(static_cast<LPCSTR>(text));
    return;
  }
  Pass();
}

void RuntimeScriptScenario::FailScript(const char* text, const char* file, int line) {
  scriptArmedOrFinished = true;
  FailScenarioText(
      static_cast<LPCSTR>(RuntimeAssertionText::Failure(RunState(), text, file, line)));
}

void RuntimeScriptScenario::FailRequirement(const char* expression, const char* file, int line) {
  scriptArmedOrFinished = true;
  FailScenarioText(
      static_cast<LPCSTR>(RuntimeAssertionText::Requirement(RunState(), expression, file, line)));
}

void RuntimeScriptScenario::FailRequirementRelation(const char* expression, const char* relation,
                                                    const CString& expected, const CString& actual,
                                                    const char* file, int line) {
  scriptArmedOrFinished = true;
  FailScenarioTextAs(RuntimeAssertionText::PhaseSlug(expression),
                     static_cast<LPCSTR>(RuntimeAssertionText::RequirementValues(
                         RunState(), expression, relation, expected, actual, file, line)));
}

void RuntimeScriptScenario::FailRequirementKindOf(const char* expression, const char* typeName,
                                                  TView* view, const char* file, int line) {
  scriptArmedOrFinished = true;
  FailScenarioTextAs(
      RuntimeAssertionText::PhaseSlug(expression),
      static_cast<LPCSTR>(RuntimeAssertionText::RequirementValues(
          RunState(), expression, "is a", RuntimeAssertionText::Value(typeName),
          RuntimeAssertionText::Value(view != 0 ? RuntimeClassName(view) : "null"), file, line)));
}

void RuntimeScriptScenario::RecordCheckFailure(const char* expression, const char* file, int line) {
  ++checkFailures;
  // Recorded, not terminal: the point of RT_CHECK is to report several problems from one run.
  RunState().RecordAssertion(RuntimeAssertionText::PhaseSlug(expression),
                             static_cast<LPCSTR>(RuntimeAssertionText::RequirementJson(
                                 RunState(), expression, file, line)),
                             false);
}
