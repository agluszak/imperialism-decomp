#pragma once

#include "RuntimeTestCase.h"

class LegacyJourneyTest : public RuntimeTestCase {
public:
  void Start(RuntimeContext&) override {}
  void Tick(RuntimeContext&) override {
    OnIdle();
  }
  void ObserveTurnEvent(RuntimeContext&, int eventCode) override {
    ObserveActivatedTurnEvent(eventCode);
  }
  void ObserveBuiltUiTree(RuntimeContext&, int eventCode, TView* root) override {
    ObserveBuiltUiTree(eventCode, root);
  }
  unsigned int RandomSeed(RuntimeContext&) override {
    return RandomSeed();
  }

  static void OnIdle();
  static void ObserveBuiltUiTree(int eventCode, TView* root);
  static void ObserveActivatedTurnEvent(int eventCode);
  static unsigned int RandomSeed();
};
