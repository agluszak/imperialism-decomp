#include "RuntimeTestDriver.h"

#include "RuntimeHarness.h"
#include "RuntimeUiDriver.h"

bool RuntimeTestDriver::HandleMessage(MSG* message) {
  return RuntimeHarness::HandleMessage(message);
}

void RuntimeTestDriver::OnIdle() {
  RuntimeHarness::OnIdle();
}

void RuntimeTestDriver::ObserveBuiltUiTree(int eventCode, TView* root) {
  RuntimeHarness::ObserveBuiltUiTree(eventCode, root);
}

void RuntimeTestDriver::ObserveActivatedTurnEvent(int eventCode) {
  RuntimeHarness::ObserveActivatedTurnEvent(eventCode);
}

void RuntimeTestDriver::Observe(unsigned int observationKinds) {
  RuntimeHarness::Observe(observationKinds);
}

void RuntimeTestDriver::ObserveDeferred(unsigned int observationKinds) {
  RuntimeUiDriver::PostObservation(observationKinds);
}

void RuntimeTestDriver::Pulse() {
  RuntimeHarness::Pulse();
}

unsigned int RuntimeTestDriver::RandomSeed() {
  return RuntimeHarness::RandomSeed();
}
