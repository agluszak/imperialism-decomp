#include "RuntimeRun.h"

#include <windows.h>

RuntimeRun::RuntimeRun() : startMs(0), progressCounter(0), lastProgressMs(0) {
  lastAction[0] = 0;
}

void RuntimeRun::Start() {
  startMs = GetTickCount();
  progressCounter = 0;
  lastProgressMs = 0;
  lastAction[0] = 0;
}

void RuntimeRun::MarkProgress(const char* action) {
  lstrcpynA(lastAction, action, sizeof(lastAction));
  ++progressCounter;
  lastProgressMs = ElapsedMs();
}

void RuntimeRun::MarkFallbackProgress() {
  ++progressCounter;
  lastProgressMs = ElapsedMs();
}

unsigned long RuntimeRun::ElapsedMs() const {
  return GetTickCount() - startMs;
}

unsigned long RuntimeRun::ProgressCounter() const {
  return progressCounter;
}

unsigned long RuntimeRun::LastProgressMs() const {
  return lastProgressMs;
}

const char* RuntimeRun::LastAction() const {
  return lastAction;
}
