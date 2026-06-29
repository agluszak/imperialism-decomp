#include "game/TBackdropWindow.h"

#include "game/CMainFrame.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/app_init_globals.h"
#include "game/global_data_tables.h"

namespace {

void ReleaseTempMapWaitCursorBufferIfNeeded() {
  void* tempBuffer = DAT_006a2054;
  if (tempBuffer != NULL) {
    AfxGetModuleState();
    AfxGetApp()->EndWaitCursor();
    delete static_cast<char*>(tempBuffer);
  }
  DAT_006a2054 = NULL;
}

CWnd* GetMainWndViaDoubleAfxGetThread() {
  CWinThread* thread = AfxGetThread();
  if (thread == NULL) {
    return NULL;
  }
  thread = AfxGetThread();
  return thread->GetMainWnd();
}

} // namespace

BEGIN_MESSAGE_MAP(TBackdropWindow, CWnd)
ON_WM_CREATE()
ON_WM_PAINT()
ON_WM_TIMER()
END_MESSAGE_MAP()

// SYNTHETIC: IMPERIALISM 0x0049cbc0
// TBackdropWindow::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049cbf0
TBackdropWindow::~TBackdropWindow() {
  DAT_006a2050 = NULL;
}

TBackdropWindow::TBackdropWindow() : CWnd(), m_backdropBmp(NULL) {}

// FUNCTION: IMPERIALISM 0x0049cc60
void WrapperFor_AllocateWithFallbackHandler_At0049cc60(CWnd* parent) {
  if (g_cachedAppShellCommand == 0 || DAT_006a2050 != NULL) {
    return;
  }

  TBackdropWindow* window = new TBackdropWindow();
  DAT_006a2050 = window;
  if (window == NULL) {
    return;
  }

  window->m_backdropBmp = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(0x3b6);
  if (window->m_backdropBmp != NULL) {
    CPoint size;
    window->m_backdropBmp->CopyBitmapDimensionsToPoint(&size);
    HWND parentHwnd = (parent != NULL) ? parent->m_hWnd : NULL;
    AfxGetModuleState();
    HCURSOR cursor = ::LoadCursorA(NULL, MAKEINTRESOURCEA(0x7f00));
    LPCSTR wndClass = AfxRegisterWndClass(0, cursor, NULL, NULL);
    window->CreateEx(0, wndClass, NULL, 0x90000000, 0, 0, size.x, size.y, parentHwnd, NULL, NULL);
  }

  if (window->m_hWnd == NULL) {
    if (DAT_006a2050 != NULL) {
      delete DAT_006a2050;
    }
    DAT_006a2050 = NULL;
    return;
  }

  ::UpdateWindow(DAT_006a2050->m_hWnd);
}

// FUNCTION: IMPERIALISM 0x0049cca0
void CreateGlobalBackdropWindowWithDefaultBmp3B6(TBackdropWindow* window, CWnd* parent) {
  DAT_006a2050 = window;
  if (window == NULL) {
    return;
  }

  window->InitializeDefaultBackdropWindowFromBmp3B6(parent);

  if (window->m_hWnd == NULL) {
    if (DAT_006a2050 != NULL) {
      delete DAT_006a2050;
    }
    DAT_006a2050 = NULL;
    return;
  }

  ::UpdateWindow(DAT_006a2050->m_hWnd);
}

// FUNCTION: IMPERIALISM 0x0049cdf0
void RefreshBackdropOnInputMessages(MSG* msg) {
  if (DAT_006a2050 == NULL || msg == NULL) {
    return;
  }

  UINT message = msg->message;
  if (message != WM_KEYDOWN && message != WM_SYSKEYDOWN && message != WM_LBUTTONDOWN &&
      message != WM_RBUTTONDOWN && message != WM_MBUTTONDOWN && message != WM_NCLBUTTONDOWN &&
      message != WM_NCRBUTTONDOWN && message != WM_NCMBUTTONDOWN) {
    return;
  }

  DAT_006a2050->DestroyWindow();

  CWnd* mainWnd = GetMainWndViaDoubleAfxGetThread();
  HWND hwnd = (mainWnd != NULL) ? mainWnd->m_hWnd : NULL;
  ::UpdateWindow(hwnd);
}

// FUNCTION: IMPERIALISM 0x0049ce90
void TBackdropWindow::InitializeDefaultBackdropWindowFromBmp3B6(CWnd* parent) {
  m_backdropBmp = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(0x3b6);
  if (m_backdropBmp == NULL) {
    return;
  }

  CPoint size;
  m_backdropBmp->CopyBitmapDimensionsToPoint(&size);
  HWND parentHwnd = (parent != NULL) ? parent->m_hWnd : NULL;
  AfxGetModuleState();
  HCURSOR cursor = ::LoadCursorA(NULL, MAKEINTRESOURCEA(0x7f00));
  LPCSTR wndClass = AfxRegisterWndClass(0, cursor, NULL, NULL);
  CreateEx(0, wndClass, NULL, 0x90000000, 0, 0, size.x, size.y, parentHwnd, NULL, NULL);
}

// FUNCTION: IMPERIALISM 0x0049cfa0
void TBackdropWindow::PostNcDestroy() {
  g_pModuleLibraryCacheState->ReleaseRecordByHandle(m_backdropBmp);
  m_backdropBmp = NULL;
  delete this;
  DAT_006a2050 = NULL;

  CWnd* mainWnd = GetMainWndViaDoubleAfxGetThread();
  static_cast<CMainFrame*>(mainWnd)->ConfigureTopLevelWindowStyleAndPlacement(0x280, 0x1e0);

  mainWnd = GetMainWndViaDoubleAfxGetThread();
  mainWnd->SetWindowPos(NULL, 0, 0, 0, 0, 5);

  ReleaseTempMapWaitCursorBufferIfNeeded();
}

// FUNCTION: IMPERIALISM 0x0049d090
int TBackdropWindow::OnCreate(LPCREATESTRUCT lpCreateStruct) {
  if (CWnd::OnCreate(lpCreateStruct) == -1) {
    return -1;
  }

  CenterWindow(NULL);
  ::SetTimer(m_hWnd, 1, 0x2ee, NULL);

  ReleaseTempMapWaitCursorBufferIfNeeded();
  char* waitCursorToken = new char(0);
  if (waitCursorToken != NULL) {
    AfxGetModuleState();
    AfxGetApp()->BeginWaitCursor();
  }
  DAT_006a2054 = waitCursorToken;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049d180
void TBackdropWindow::OnPaint() {
  CPaintDC paintDC(this);
  if (m_backdropBmp == NULL) {
    return;
  }

  CPoint size;
  m_backdropBmp->SelectAndRealizeDibPalette(&paintDC, FALSE);
  m_backdropBmp->CopyBitmapDimensionsToPoint(&size);
  m_backdropBmp->StretchDibitsFromStoredBitmapToHdcSimple(&paintDC, 0, 0, size.x, size.y);
}

void TBackdropWindow::OnTimer(UINT timerId) {
  if (timerId == 1) {
    DestroyWindow();
    return;
  }
  CWnd::OnTimer(timerId);
}
