#include "game/TMovieView.h"

#include "game/CMainFrame.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include "game/movie_window_library.h"

IMPLEMENT_DYNCREATE(TMovieView, TPicture)

namespace {

// FUNCTION: IMPERIALISM 0x00492f60
MciMovieWindowState* InitializeMovieViewOwnedStateBlock_Impl(MciMovieWindowState* state,
                                                             HWND parentHwnd) {
  AFX_MODULE_STATE* moduleState = AfxGetModuleState();
  state->hwnd =
      MCIWndCreateA(parentHwnd, moduleState->m_hCurrentInstanceHandle,
                    kMciMovieWindowCreateStyle, 0);
  state->lastResult = 0;
  return state;
}

// FUNCTION: IMPERIALISM 0x00492fa0
void SendWmCloseToWindowHandle(MciMovieWindowState* state) {
  SendMessageA(state->hwnd, WM_CLOSE, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00492fc0
bool SendMessage499AndDetachOnSuccess(MciMovieWindowState* state, LPCSTR moviePath) {
  state->lastResult = SendMessageA(state->hwnd, kMciMovieOpenMessage, 0,
                                   reinterpret_cast<LPARAM>(moviePath));
  if (state->lastResult != 0) {
    return false;
  }

  CWnd window;
  window.Attach(state->hwnd);
  window.CenterWindow();
  window.Detach();
  return true;
}

// FUNCTION: IMPERIALISM 0x00493090
bool SendMessage806AndCacheResult(MciMovieWindowState* state) {
  state->lastResult = SendMessageA(state->hwnd, kMciMoviePlayMessage, 0, 0);
  return state->lastResult == 0;
}

// FUNCTION: IMPERIALISM 0x004930d0
bool SendMessage808AndCacheResult(MciMovieWindowState* state) {
  state->lastResult = SendMessageA(state->hwnd, kMciMoviePollMessage, 0, 0);
  return state->lastResult == 0;
}

CMainFrame* GetMovieMainFrame() {
  CWinThread* thread = AfxGetThread();
  if (thread == 0) {
    return 0;
  }
  return static_cast<CMainFrame*>(thread->GetMainWnd());
}

} // namespace

// FUNCTION: IMPERIALISM 0x005e2230
TMovieView::TMovieView() : TPicture(), movieWindowState(0) {
  g_pSfxPlaybackSystem->ClearDirectSoundInitPendingAndResetState();
  g_pSfxPlaybackSystem->HandleBlinkStateAndScheduleTimerTick(1);

  CMainFrame* mainFrame = GetMovieMainFrame();
  if (mainFrame != 0) {
    mainFrame->SetFieldC0AndInvalidateWindowIfChanged(0x1000000);
  } else {
    static_cast<CMainFrame*>(0)->SetFieldC0AndInvalidateWindowIfChanged(0x1000000);
  }
}

// SYNTHETIC: IMPERIALISM 0x005e22f0
// TMovieView::`scalar deleting destructor'
TMovieView::~TMovieView() {
  if (movieWindowState != 0) {
    SendWmCloseToWindowHandle(movieWindowState);
    delete movieWindowState;
    movieWindowState = 0;
  }

  CMainFrame* mainFrame = GetMovieMainFrame();
  if (mainFrame != 0) {
    mainFrame->SetFieldC0AndInvalidateWindowIfChanged(0x100005f);
  } else {
    static_cast<CMainFrame*>(0)->SetFieldC0AndInvalidateWindowIfChanged(0x100005f);
  }

  g_pSfxPlaybackSystem->RequestDirectSoundInitIfAllowed();
}

// FUNCTION: IMPERIALISM 0x005e23f0
void TMovieView::NoOpUiLifecycleHook(int arg) {
  TPicture::NoOpUiLifecycleHook(arg);

  TView* owner = OwnerPanel();
  CWnd* nativeWindow = owner->nativeWindow50;
  HWND parentHwnd = 0;
  if (nativeWindow != 0) {
    parentHwnd = nativeWindow->m_hWnd;
  }

  movieWindowState = 0;
  MciMovieWindowState* state = new MciMovieWindowState();
  if (state != 0) {
    movieWindowState = InitializeMovieViewOwnedStateBlock_Impl(state, parentHwnd);
  }
}

// FUNCTION: IMPERIALISM 0x005e2490
void TMovieView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x005e24b0
bool TMovieView::OpenMoviePathAndDetachOnSuccess(LPCSTR moviePath) {
  if (movieWindowState == 0) {
    return false;
  }
  return SendMessage499AndDetachOnSuccess(movieWindowState, moviePath);
}

// FUNCTION: IMPERIALISM 0x005e24e0
bool TMovieView::SendMessage806IfSelectionStateActive() {
  if (movieWindowState == 0) {
    return false;
  }
  return SendMessage806AndCacheResult(movieWindowState);
}

// FUNCTION: IMPERIALISM 0x005e2500
bool TMovieView::SendMessage808IfSelectionStateActive() {
  if (movieWindowState == 0) {
    return false;
  }
  return SendMessage808AndCacheResult(movieWindowState);
}

// FUNCTION: IMPERIALISM 0x005e2520
char TMovieView::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  if (movieWindowState != 0) {
    SendMessage808AndCacheResult(movieWindowState);
  }
  return TPicture::DispatchUiMouseMoveToChildren(point, arg2, arg3, arg4);
}

