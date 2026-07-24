#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeHarness is test-only and must not be included in the production build
#endif

class RuntimeContext;
class RuntimeTestCase;
class TView;

class RuntimeHarness {
public:
  static void OnIdle();
  static void ObserveBuiltUiTree(int eventCode, TView* root);
  static void ObserveActivatedTurnEvent(int eventCode);
  static unsigned int RandomSeed();

private:
  static void EnsureSelected();
};
