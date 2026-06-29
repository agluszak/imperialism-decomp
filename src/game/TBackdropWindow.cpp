#include "game/TBackdropWindow.h"

#include "game/CMainFrame.h"
#include "game/TModuleLibraryCacheTableStateB.h"
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

} // namespace

// SYNTHETIC: IMPERIALISM 0x0049cbc0
// TBackdropWindow::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049cbf0
TBackdropWindow::~TBackdropWindow() {
  DAT_006a2050 = NULL;
}

TBackdropWindow::TBackdropWindow() : CWnd(), m_backdropBmp(NULL) {}

// FUNCTION: IMPERIALISM 0x0049cca0
void CreateGlobalBackdropWindowWithDefaultBmp3B6(CWnd* parent) {
  if (DAT_006a2050 != NULL) {
    return;
  }

  TBackdropWindow* window = new TBackdropWindow();
  DAT_006a2050 = window;
  if (window != NULL) {
    window->InitializeDefaultBackdropWindowFromBmp3B6(parent);
  }

  if (window == NULL || window->m_hWnd == NULL) {
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

  CWinThread* thread = AfxGetThread();
  CWnd* mainWnd = (thread != NULL) ? thread->GetMainWnd() : NULL;
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
void TBackdropWindow::ResetTopLevelWindowStateAndReleaseTempMapBuffer() {
  g_pModuleLibraryCacheState->ReleaseRecordByHandle(m_backdropBmp);
  m_backdropBmp = NULL;
  delete this;
  DAT_006a2050 = NULL;

  CWinThread* thread = AfxGetThread();
  CMainFrame* mainFrame = NULL;
  if (thread != NULL) {
    mainFrame = static_cast<CMainFrame*>(thread->GetMainWnd());
  }
  if (mainFrame != NULL) {
    mainFrame->ConfigureTopLevelWindowStyleAndPlacement(0x280, 0x1e0);
  }

  thread = AfxGetThread();
  CWnd* mainWnd = (thread != NULL) ? thread->GetMainWnd() : NULL;
  if (mainWnd != NULL) {
    mainWnd->SetWindowPos(NULL, 0, 0, 0, 0, 5);
  }

  ReleaseTempMapWaitCursorBufferIfNeeded();
}
