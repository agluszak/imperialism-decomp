#include "RuntimeTestDriver.h"

#include "RuntimeHarness.h"

void RuntimeTestDriver::OnIdle() {
  RuntimeHarness::OnIdle();
}

void RuntimeTestDriver::ObserveBuiltUiTree(int eventCode, TView* root) {
  RuntimeHarness::ObserveBuiltUiTree(eventCode, root);
}

void RuntimeTestDriver::ObserveActivatedTurnEvent(int eventCode) {
  RuntimeHarness::ObserveActivatedTurnEvent(eventCode);
}

void RuntimeTestDriver::Pulse() {
  RuntimeHarness::Pulse();
}

unsigned int RuntimeTestDriver::RandomSeed() {
  return RuntimeHarness::RandomSeed();
}
