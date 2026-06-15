#include "game/mfc.h"

typedef void(__cdecl* TempMapLockCallback)(int);
typedef int(__cdecl* AllocFallbackCallback)(undefined4);

static TempMapLockCallback ResolveTempMapLockCallback(int module_thread_state) {
  if (module_thread_state == 0) {
    return 0;
  }
  int module_state = *(int*)(module_thread_state + 4);
  if (module_state == 0) {
    return 0;
  }
  return *(TempMapLockCallback*)(module_state + 0x98);
}

// LIBRARY: IMPERIALISM 0x00606c67
// AfxGetApp()->BeginWaitCursor (BeginWaitCursor)

// LIBRARY: IMPERIALISM 0x00606c7c
// EndWaitCursor

// FUNCTION: IMPERIALISM 0x00606f73
int AllocateWithFallbackHandler(undefined4 size_bytes) {
  int module_thread_state = (int)GetOrCreateMfcModuleThreadState();
  if (module_thread_state == 0) {
    return 0;
  }

  AllocFallbackCallback fallback = *(AllocFallbackCallback*)(module_thread_state + 0x28);
  if (fallback == 0) {
    return 0;
  }
  return fallback(size_bytes);
}

// FUNCTION: IMPERIALISM 0x00606faf
void FreeHeapBufferIfNotNull(undefined4 ptr_value) {
  if (ptr_value != 0) {
    reinterpret_cast<void(__cdecl*)()>(FreeHeapBlockWithAllocatorTracking)();
  }
}
