#include "RuntimeHarness.h"

#include "RuntimeContext.h"
#include "RuntimeRegistry.h"
#include "RuntimeTestCase.h"
#include "scenarios/RuntimeScenarios.h"

namespace {

RuntimeContext g_context;
RuntimeTestCase* g_testCase = 0;
const int kPendingTurnEventCapacity = 32;
int g_pendingTurnEvents[kPendingTurnEventCapacity];
int g_pendingTurnEventHead = 0;
int g_pendingTurnEventCount = 0;

} // namespace

void RuntimeHarness::EnsureSelected() {
  if (g_testCase != 0) {
    return;
  }
  g_context.InitializeFromEnvironment();
  const RuntimeTestDescriptor* descriptor = RuntimeRegistry::Find(g_context.TestName());
  g_testCase = descriptor != 0 ? descriptor->testCase : UnknownRuntimeTest();
  g_testCase->Start(g_context);
}

void RuntimeHarness::OnIdle() {
  EnsureSelected();
  while (g_pendingTurnEventCount > 0) {
    int eventCode = g_pendingTurnEvents[g_pendingTurnEventHead];
    g_pendingTurnEventHead = (g_pendingTurnEventHead + 1) % kPendingTurnEventCapacity;
    --g_pendingTurnEventCount;
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
  if (g_pendingTurnEventCount == kPendingTurnEventCapacity) {
    g_pendingTurnEventHead = (g_pendingTurnEventHead + 1) % kPendingTurnEventCapacity;
    --g_pendingTurnEventCount;
  }
  int tail = (g_pendingTurnEventHead + g_pendingTurnEventCount) % kPendingTurnEventCapacity;
  g_pendingTurnEvents[tail] = eventCode;
  ++g_pendingTurnEventCount;
}

unsigned int RuntimeHarness::RandomSeed() {
  EnsureSelected();
  return g_testCase->RandomSeed(g_context);
}
