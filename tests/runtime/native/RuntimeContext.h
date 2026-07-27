#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeContext is test-only and must not be included in the production build
#endif

class RuntimeRun;

class RuntimeContext {
public:
  explicit RuntimeContext(RuntimeRun& run);

  void InitializeFromEnvironment();
  const char* TestName() const;
  unsigned int Seed() const;
  RuntimeRun& Run() const;

private:
  RuntimeRun* run;
};
