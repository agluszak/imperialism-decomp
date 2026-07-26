#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeRun is test-only and must not be included in the production build
#endif

class RuntimeRun {
public:
  RuntimeRun();

  void Start();
  void MarkProgress(const char* action);
  void MarkFallbackProgress();

  unsigned long ElapsedMs() const;
  unsigned long ProgressCounter() const;
  unsigned long LastProgressMs() const;
  const char* LastAction() const;

private:
  unsigned long startMs;
  unsigned long progressCounter;
  unsigned long lastProgressMs;
  char lastAction[64];
};
