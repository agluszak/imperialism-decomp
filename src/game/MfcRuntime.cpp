#include "game/MfcRuntime.h"

typedef unsigned int u32;
typedef void* hwnd_t;
typedef u32 hmenu_t;

extern "C" u32 __stdcall SendMessageA(hwnd_t hWnd, u32 msg, u32 wParam, int lParam);
extern "C" u32 __stdcall CheckMenuItem(hmenu_t hMenu, u32 itemId, u32 flags);

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

// FUNCTION: IMPERIALISM 0x00606c67
void BeginWaitCursor(void) {
  int module_thread_state = (int)GetOrCreateMfcModuleThreadState();
  TempMapLockCallback callback = ResolveTempMapLockCallback(module_thread_state);
  if (callback != 0) {
    callback(1);
  }
}

// FUNCTION: IMPERIALISM 0x00606c7c
void EndWaitCursor(void) {
  int module_thread_state = (int)GetOrCreateMfcModuleThreadState();
  TempMapLockCallback callback = ResolveTempMapLockCallback(module_thread_state);
  if (callback != 0) {
    callback(-1);
  }
}

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
