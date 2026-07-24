#include "game/gfx/TBackdropWindow.h"

#include "game/ui_core/CMainFrame.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/app_init_globals.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

namespace {

void ReleaseTempMapWaitCursorBufferIfNeeded() {
  char* tempBuffer = g_pBackdropWaitCursorGuardToken;
  if (tempBuffer != NULL) {
    AfxGetModuleState();
    AfxGetApp()->EndWaitCursor();
    delete tempBuffer;
  }
  g_pBackdropWaitCursorGuardToken = NULL;
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

// clang-cl's lint build rejects the MFC message-map macros' unqualified `&OnPaint`-style
// address-of-member-function (a long-standing MSVC extension clang doesn't implement for
// this context); this is MFC dispatch-table plumbing, not game logic, so it's skipped in
// the compile-only lint build (never linked, so the missing definition is harmless there).
#ifndef IMPERIALISM_LINT
// SYNTHETIC: IMPERIALISM 0x0049cc20
// TBackdropWindow::GetMessageMap
BEGIN_MESSAGE_MAP(TBackdropWindow, CWnd)
ON_WM_CREATE()
ON_WM_PAINT()
ON_WM_TIMER()
END_MESSAGE_MAP()
#endif

// SYNTHETIC: IMPERIALISM 0x0049cbc0
// TBackdropWindow::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049cbf0
TBackdropWindow::~TBackdropWindow() {
  g_pActiveBackdropWindow = NULL;
}

TBackdropWindow::TBackdropWindow() : CWnd(), m_backdropBmp(NULL) {}

// FUNCTION: IMPERIALISM 0x0049cc60
void Function_0049cc60(CWnd* parent) {
  if (!g_cachedShowSplashFlag || g_pActiveBackdropWindow != NULL) {
    return;
  }

  TBackdropWindow* window = new TBackdropWindow();
  g_pActiveBackdropWindow = window;
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
    if (g_pActiveBackdropWindow != NULL) {
      delete g_pActiveBackdropWindow;
    }
    g_pActiveBackdropWindow = NULL;
    return;
  }

  ::UpdateWindow(g_pActiveBackdropWindow->m_hWnd);
}

// FUNCTION: IMPERIALISM 0x0049cca0
void CreateGlobalBackdropWindowWithDefaultBmp3B6(TBackdropWindow* window, CWnd* parent) {
  g_pActiveBackdropWindow = window;
  if (window == NULL) {
    return;
  }

  window->InitializeDefaultBackdropWindowFromBmp3B6(parent);

  if (window->m_hWnd == NULL) {
    if (g_pActiveBackdropWindow != NULL) {
      delete g_pActiveBackdropWindow;
    }
    g_pActiveBackdropWindow = NULL;
    return;
  }

  ::UpdateWindow(g_pActiveBackdropWindow->m_hWnd);
}

// FUNCTION: IMPERIALISM 0x0049cdf0
void RefreshBackdropOnInputMessages(MSG* msg) {
  if (g_pActiveBackdropWindow == NULL || msg == NULL) {
    return;
  }

  UINT message = msg->message;
  if (message != WM_KEYDOWN && message != WM_SYSKEYDOWN && message != WM_LBUTTONDOWN &&
      message != WM_RBUTTONDOWN && message != WM_MBUTTONDOWN && message != WM_NCLBUTTONDOWN &&
      message != WM_NCRBUTTONDOWN && message != WM_NCMBUTTONDOWN) {
    return;
  }

  g_pActiveBackdropWindow->DestroyWindow();

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
  g_pActiveBackdropWindow = NULL;

  CWnd* mainWnd = GetMainWndViaDoubleAfxGetThread();
  if (mainWnd != NULL) {
    static_cast<CMainFrame*>(mainWnd)->ConfigureTopLevelWindowStyleAndPlacement(0x280, 0x1e0);
  }

  mainWnd = GetMainWndViaDoubleAfxGetThread();
  if (mainWnd != NULL) {
    mainWnd->SetWindowPos(NULL, 0, 0, 0, 0, 5);
  }

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
  g_pBackdropWaitCursorGuardToken = waitCursorToken;
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

// FUNCTION: IMPERIALISM 0x0049d240
void TBackdropWindow::OnTimer(UINT timerId) {
  (void)timerId;
  DestroyWindow();
  CWnd* mainWnd = GetMainWndViaDoubleAfxGetThread();
  ::UpdateWindow(mainWnd->m_hWnd);
}
