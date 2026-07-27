#include "RuntimeScenario.h"

namespace {

class BootManagersTestCase : public RuntimeScenario {
public:
  bool RequiresMainWindow() const override {
    return false;
  }
  void OnManagersReady() override {
    Pass();
  }
};

BootManagersTestCase g_test;

} // namespace

RuntimeTestCase* BootManagersTest() {
  return &g_test;
}
