#include "RuntimeScenario.h"

namespace {

class RandomGameJourneyTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "random_game_enters_map";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
};

RandomGameJourneyTestCase g_test;

} // namespace

RuntimeTestCase* RandomGameJourneyTest() {
  return &g_test;
}
