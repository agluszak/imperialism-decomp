#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"

namespace {

class EasyRandomGameTestCase : public RandomGameScenario {
public:
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
