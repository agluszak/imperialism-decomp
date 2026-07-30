#include "RuntimeHarness.h"

#include "RuntimeContext.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"
#include "RuntimeTestCase.h"
#include "RuntimeTurnEventQueue.h"
#include "RuntimeUiDriver.h"
#include "RuntimeJson.h"
// Generated from tools/runtime/catalog.py; supplies UnknownRuntimeTest for an unrecognised
// IMPERIALISM_RUNTIME_TEST name.
#include "RuntimeScenarioFactories.inc"

namespace {

RuntimeRun g_run;
RuntimeContext g_context(g_run);
RuntimeTestCase* g_testCase = 0;
RuntimeTurnEventQueue g_pendingTurnEvents;

} // namespace

bool RuntimeHarness::HandleMessage(MSG* message) {
  if (message == 0 || message->message != WM_RUNTIME_ACTION) {
    return false;
  }
  EnsureSelected();
  CString failure;
  if (!RuntimeUiDriver::HandlePostedAction(&failure)) {
    CString failureJson;
    RuntimeJson::AppendString(failureJson, failure);
    g_testCase->FailHarness(g_context, failureJson);
  }
  return true;
}

void RuntimeHarness::EnsureSelected() {
  if (g_testCase != 0) {
    return;
  }
  g_context.InitializeFromEnvironment();
  const RuntimeTestDescriptor* descriptor = RuntimeRegistry::Find(g_context.TestName());
  g_testCase = descriptor != 0 ? descriptor->testCase : UnknownRuntimeTest();
  if (descriptor != 0) {
    g_run.SetDescriptor(descriptor->snapshotFlags, descriptor->evidenceKind);
  }
  g_testCase->Start(g_context);
}

void RuntimeHarness::OnIdle() {
  EnsureSelected();
  int eventCode;
  while (g_pendingTurnEvents.Pop(eventCode)) {
    g_testCase->ObserveTurnEvent(g_context, eventCode);
    g_testCase->Observe(g_context, kObserveTurnEventActivated);
  }
  g_testCase->Observe(g_context, kObserveApplicationIdle);
}

void RuntimeHarness::ObserveBuiltUiTree(int eventCode, TView* root) {
  EnsureSelected();
  g_testCase->ObserveBuiltUiTree(g_context, eventCode, root);
  g_testCase->Observe(g_context, kObserveUiTreeBuilt | kObserveMainViewChanged);
}

void RuntimeHarness::Observe(unsigned int observationKinds) {
  EnsureSelected();
  g_testCase->Observe(g_context, observationKinds);
}

void RuntimeHarness::ObserveActivatedTurnEvent(int eventCode) {
  EnsureSelected();
  if (!g_pendingTurnEvents.Push(eventCode)) {
    g_testCase->FailHarness(
        g_context, "\"runtime harness turn-event queue overflowed before idle observation\"");
  }
}

void RuntimeHarness::Pulse() {
  EnsureSelected();
  g_testCase->Pulse(g_context);
  g_testCase->Observe(g_context, kObserveGameStateChanged);
}

unsigned int RuntimeHarness::RandomSeed() {
  EnsureSelected();
  return g_testCase->RandomSeed(g_context);
}
