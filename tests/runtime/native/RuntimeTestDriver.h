#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeTestDriver is test-only and must not be included in the production build
#endif

class TView;

class RuntimeTestDriver {
public:
  static void OnIdle();
  static void ObserveBuiltUiTree(int eventCode, TView* root);
  static void ObserveActivatedTurnEvent(int eventCode);
  static unsigned int RandomSeed();
};
