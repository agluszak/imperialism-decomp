#include "game/mfc.h"

typedef void(__cdecl* TempMapLockCallback)(int);

#include "game/ImperialismApp.h"

undefined4 GetOrCreateMfcModuleThreadState(void) {
  return WrapperFor_GetOrCreateMfcModuleThreadState_At004139f0();
}

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

// LIBRARY: IMPERIALISM 0x00608115
// CWnd::CreateEx

// LIBRARY: IMPERIALISM 0x0060a27d
// CWnd::CenterWindow

// LIBRARY: IMPERIALISM 0x006073b4
// CWnd::SetWindowText(LPCTSTR)

// LIBRARY: IMPERIALISM 0x0060753b
// CWnd::EnableWindow(BOOL)

// LIBRARY: IMPERIALISM 0x0060859f
// CWnd::GetWindowText(CString&) const

// LIBRARY: IMPERIALISM 0x0060d3fc
// AfxWinMain

// LIBRARY: IMPERIALISM 0x0061852a
// CWinApp::DoMessageBox

// LIBRARY: IMPERIALISM 0x006185e4
// AfxMessageBox (LPCTSTR, UINT, UINT) — forwards to AfxGetApp()->DoMessageBox

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
