#include "RuntimeScriptFragment.h"

RuntimeScriptFragment::RuntimeScriptFragment() : host(0), fragmentProgramCounter(0) {}

void RuntimeScriptFragment::BeginFragment(RuntimeScriptScenario& scenario) {
  host = &scenario;
  fragmentProgramCounter = 0;
}

bool RuntimeScriptFragment::IsBound() const {
  return host != 0;
}

RuntimeScriptScenario& RuntimeScriptFragment::Host() const {
  return *host;
}

int RuntimeScriptFragment::FragmentProgramCounter() const {
  return fragmentProgramCounter;
}

void RuntimeScriptFragment::SetFragmentProgramCounter(int slot) {
  fragmentProgramCounter = slot;
}

void RuntimeScriptFragment::AwaitFragment(unsigned int observationKinds, const char* expression,
                                          const char* file, int line) {
  host->AwaitScript(observationKinds, expression, file, line);
}

bool RuntimeScriptFragment::ScreenIsCurrentForFragment(CRuntimeClass* viewClass,
                                                       int eventCode) const {
  return host->ScreenIsCurrent(viewClass, eventCode);
}

void RuntimeScriptFragment::AwaitScreenFragment(CRuntimeClass* viewClass, int eventCode,
                                                const char* className, const char* file, int line) {
  host->AwaitScreenScript(viewClass, eventCode, className, file, line);
}

bool RuntimeScriptFragment::RunFragmentAction(const char* label, const RuntimeActionResult& result,
                                              const char* file, int line) {
  return host->RunScriptAction(label, result, file, line);
}

void RuntimeScriptFragment::FailFragment(const char* text, const char* file, int line) {
  host->FailScript(text, file, line);
}

void RuntimeScriptFragment::FailFragmentRequirement(const char* expression, const char* file,
                                                    int line) {
  host->FailRequirement(expression, file, line);
}

int RuntimeScriptFragment::CurrentTurnEventForFragment() const {
  return host->CurrentTurnEvent();
}

void RuntimeScriptFragment::ContinueFragmentAfterAction() {
  host->ContinueAfterAction();
}

void RuntimeScriptFragment::RecordHandledModalForFragment(const char* label) {
  host->RecordHandledModal(label);
}

void RuntimeScriptFragment::RecordUnexpectedModalForFragment(TView* modal) {
  host->RecordUnexpectedModalView(modal);
}

bool RuntimeScriptFragment::AdvanceNewspaperForFragment() {
  return host->AdvanceNewspaperIfNeeded();
}

void RuntimeScriptFragment::ResetNewspaperAdvanceForFragment() {
  host->ResetNewspaperAdvance();
}
