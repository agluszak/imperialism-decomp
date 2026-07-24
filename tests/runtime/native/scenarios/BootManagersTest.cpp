#include "RuntimeScenario.h"

namespace {

class BootManagersTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "boot_managers";
  }
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
