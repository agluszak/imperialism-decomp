#include "RuntimeHarness.h"

#include "RuntimeContext.h"
#include "RuntimeRegistry.h"
#include "RuntimeTestCase.h"
#include "scenarios/RuntimeScenarios.h"

namespace {

RuntimeContext g_context;
RuntimeTestCase* g_testCase = 0;
RuntimeTurnEventQueue g_pendingTurnEvents;

} // namespace

RuntimeTurnEventQueue::RuntimeTurnEventQueue() : head(0), count(0) {}

bool RuntimeTurnEventQueue::Push(int eventCode) {
  if (count == kCapacity) {
    return false;
  }
  int tail = (head + count) % kCapacity;
  events[tail] = eventCode;
  ++count;
  return true;
}

bool RuntimeTurnEventQueue::Pop(int& eventCode) {
  if (count == 0) {
    return false;
  }
  eventCode = events[head];
  head = (head + 1) % kCapacity;
  --count;
  return true;
}

int RuntimeTurnEventQueue::Count() const {
  return count;
}

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
        g_context,
        "\"runtime harness turn-event queue overflowed before idle observation\"");
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
