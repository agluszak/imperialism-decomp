// Manual reconstruction of small MFC/utility helpers.

#include "decomp_types.h"

typedef unsigned int u32;
typedef void *hwnd_t;
typedef u32 hmenu_t;

extern "C" u32 __stdcall SendMessageA(hwnd_t hWnd, u32 msg, u32 wParam, int lParam);
extern "C" u32 __stdcall CheckMenuItem(hmenu_t hMenu, u32 itemId, u32 flags);

undefined4 GetOrCreateMfcModuleThreadState(void);
undefined4 FreeHeapBlockWithAllocatorTracking(void);

typedef void (__cdecl *TempMapLockCallback)(int);
typedef int (__cdecl *AllocFallbackCallback)(undefined4);

static TempMapLockCallback ResolveTempMapLockCallback(int module_thread_state)
{
  if (module_thread_state == 0) {
    return 0;
  }
  int module_state = *(int *)(module_thread_state + 4);
  if (module_state == 0) {
    return 0;
  }
  return *(TempMapLockCallback *)(module_state + 0x98);
}

// FUNCTION: IMPERIALISM 0x00606c67
void LockMfcTempMaps(void)
{
  int module_thread_state = GetOrCreateMfcModuleThreadState();
  TempMapLockCallback callback = ResolveTempMapLockCallback(module_thread_state);
  if (callback != 0) {
    callback(1);
  }
}

// FUNCTION: IMPERIALISM 0x00606c7c
void UnlockMfcTempMaps(void)
{
  int module_thread_state = GetOrCreateMfcModuleThreadState();
  TempMapLockCallback callback = ResolveTempMapLockCallback(module_thread_state);
  if (callback != 0) {
    callback(-1);
  }
}

// FUNCTION: IMPERIALISM 0x00606ddd
void SetCommandCheckStateOnButtonOrMenu(int command_ui, u32 checked_state)
{
  int menu_context = *(int *)(command_ui + 0xc);
  if (menu_context == 0) {
    int owner_object = *(int *)(command_ui + 0x14);
    int owner_hwnd = owner_object != 0 ? *(int *)(owner_object + 0x1c) : 0;
    u32 style_bits = SendMessageA((hwnd_t)owner_hwnd, 0x87, 0, 0);
    if ((style_bits & 0x2000U) != 0) {
      SendMessageA((hwnd_t)owner_hwnd, 0xF1, checked_state, 0);
    }
    return;
  }

  if (*(int *)(command_ui + 0x10) == 0) {
    u32 menu_item_id = *(u32 *)(command_ui + 8);
    hmenu_t menu_handle = *(hmenu_t *)(menu_context + 4);
    u32 flags = 4U | ((checked_state != 0) ? 8U : 0U);
    CheckMenuItem(menu_handle, menu_item_id, flags);
  }
}

// FUNCTION: IMPERIALISM 0x00606f73
int AllocateWithFallbackHandler(undefined4 size_bytes)
{
  int module_thread_state = (int)GetOrCreateMfcModuleThreadState();
  if (module_thread_state == 0) {
    return 0;
  }

  AllocFallbackCallback fallback = *(AllocFallbackCallback *)(module_thread_state + 0x28);
  if (fallback == 0) {
    return 0;
  }
  return fallback(size_bytes);
}

// FUNCTION: IMPERIALISM 0x00606faf
void FreeHeapBufferIfNotNull(undefined4 ptr_value)
{
  if (ptr_value != 0) {
    FreeHeapBlockWithAllocatorTracking();
  }
}
