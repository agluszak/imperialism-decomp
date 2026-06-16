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

// LIBRARY: IMPERIALISM 0x006067a2
// CWinApp::ProcessMessageFilter

// LIBRARY: IMPERIALISM 0x00607673
// CWnd::AttachControlSite_607673

// LIBRARY: IMPERIALISM 0x00607706
// CWnd::CWnd

// LIBRARY: IMPERIALISM 0x00607744
// CWnd::CWnd_00607744

// LIBRARY: IMPERIALISM 0x00607782
// CWnd::CWnd_00607782

// LIBRARY: IMPERIALISM 0x006077c0
// CWnd::CWnd_006077C0

// LIBRARY: IMPERIALISM 0x00607a84
// CWnd::Default

// LIBRARY: IMPERIALISM 0x0060d3fc
// AfxWinMain

// LIBRARY: IMPERIALISM 0x0061852a
// CWinApp::DoMessageBox

// LIBRARY: IMPERIALISM 0x00618704
// CWinApp::CloseAllDocuments_618704

// LIBRARY: IMPERIALISM 0x0061873c
// CWinApp::CallField80VirtualSlot38OrReturnFalse_0061873c

// LIBRARY: IMPERIALISM 0x0062246c
// CWinThread::CWinApp

// LIBRARY: IMPERIALISM 0x00622b58
// CWinThread::CWinThread

// LIBRARY: IMPERIALISM 0x00623523
// AfxGetThreadState

// LIBRARY: IMPERIALISM 0x00623886
// AfxGetModuleState

// LIBRARY: IMPERIALISM 0x00624e73
// AfxWinInit

