#include "RuntimeDebuggerTrap.h"

#include "game/mfc.h"

RuntimeDebugRecord g_runtimeDebugRecord = {0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0};

extern "C" void ImperialismRuntimeDebuggerTrap(const RuntimeDebugRecord* record) {
  if (record != 0) {
    g_runtimeDebugRecord = *record;
  }
  char enabled[2];
  if (GetEnvironmentVariableA("IMPERIALISM_RUNTIME_TEST_DEBUGGER", enabled, sizeof(enabled)) != 0) {
    DebugBreak();
  }
}
