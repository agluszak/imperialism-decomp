#include "RuntimeContext.h"

#include <stdlib.h>
#include <windows.h>

RuntimeContext::RuntimeContext() : seed(1) {
  testName[0] = 0;
}

void RuntimeContext::InitializeFromEnvironment() {
  DWORD length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST", testName, sizeof(testName));
  if (length == 0 || length >= sizeof(testName)) {
    lstrcpyA(testName, "boot_managers");
  }

  char seedText[32];
  length = GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_SEED", seedText, sizeof(seedText));
  if (length != 0 && length < sizeof(seedText)) {
    unsigned long parsed = strtoul(seedText, 0, 10);
    if (parsed != 0) {
      seed = static_cast<unsigned int>(parsed);
    }
  }
}

const char* RuntimeContext::TestName() const {
  return testName;
}

unsigned int RuntimeContext::Seed() const {
  return seed;
}
