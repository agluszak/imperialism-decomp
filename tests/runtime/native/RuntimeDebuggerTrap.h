#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeDebuggerTrap is test-only and must not be included in the production build
#endif

class TSimMgr;
class TView;
struct _EXCEPTION_POINTERS;

enum RuntimeDebugReason { kRuntimeDebugSemanticFailure = 1, kRuntimeDebugUnhandledException = 2 };

struct RuntimeDebugRecord {
  int reason;
  unsigned long elapsedMs;
  const char* testName;
  const char* phase;
  const char* lastAction;
  int turnEvent;
  int modalDepth;
  TView* mainView;
  TView* activeModal;
  TSimMgr* simMgr;
  _EXCEPTION_POINTERS* exceptionPointers;
};

extern "C" RuntimeDebugRecord g_runtimeDebugRecord;
extern "C" void ImperialismRuntimeDebuggerTrap(const RuntimeDebugRecord* record);
