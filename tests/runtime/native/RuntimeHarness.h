#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeHarness is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

class RuntimeContext;
class RuntimeTestCase;
class TView;

class RuntimeHarness {
public:
  static bool HandleMessage(MSG* message);
  static void OnIdle();
  static void ObserveBuiltUiTree(int eventCode, TView* root);
  static void ObserveActivatedTurnEvent(int eventCode);
  static void Observe(unsigned int observationKinds);
  static void Pulse();
  static unsigned int RandomSeed();

private:
  static void EnsureSelected();
};
