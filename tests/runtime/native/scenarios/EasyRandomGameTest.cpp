#include "RuntimeScenario.h"

namespace {

class EasyRandomGameTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "random_game_easy_skips_capital";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
};

EasyRandomGameTestCase g_test;

} // namespace

RuntimeTestCase* EasyRandomGameTest() {
  return &g_test;
}
