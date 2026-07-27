#include "RuntimeHarness.h"

#include "RuntimeContext.h"
#include "RuntimeRegistry.h"
#include "RuntimeRun.h"
#include "RuntimeTestCase.h"
#include "RuntimeTurnEventQueue.h"
#include "scenarios/RuntimeScenarios.h"

namespace {

RuntimeRun g_run;
RuntimeContext g_context(g_run);
RuntimeTestCase* g_testCase = 0;
RuntimeTurnEventQueue g_pendingTurnEvents;

} // namespace

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
  }
  g_testCase->Tick(g_context);
}

void RuntimeHarness::ObserveBuiltUiTree(int eventCode, TView* root) {
  EnsureSelected();
  g_testCase->ObserveBuiltUiTree(g_context, eventCode, root);
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
}

unsigned int RuntimeHarness::RandomSeed() {
  EnsureSelected();
  return g_testCase->RandomSeed(g_context);
}
