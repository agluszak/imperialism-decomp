#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeContext is test-only and must not be included in the production build
#endif

class RuntimeContext {
public:
  RuntimeContext();

  void InitializeFromEnvironment();
  const char* TestName() const;
  unsigned int Seed() const;

private:
  char testName[64];
  unsigned int seed;
};
