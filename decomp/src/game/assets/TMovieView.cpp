#include "game/assets/TMovieView.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/CMainFrame.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/MciMovieWindowState.h"

IMPLEMENT_DYNCREATE(TMovieView, TPicture)

// FUNCTION: IMPERIALISM 0x005e2230
TMovieView::TMovieView() : TPicture() {
  g_pSfxPlaybackSystem->CancelSoundInit();
  g_pSfxPlaybackSystem->StopMusic(true);

  CMainFrame* mainFrame;
  if (AfxGetThread() != 0) {
    mainFrame = static_cast<CMainFrame*>(AfxGetThread()->GetMainWnd());
  } else {
    mainFrame = 0;
  }
  mainFrame->SetBackgroundColorAndInvalidate(PALETTEINDEX(0));
}

// FUNCTION: IMPERIALISM 0x005e2320
TMovieView::~TMovieView() {
  if (movieWindowState != 0) {
    movieWindowState->Close();
    delete movieWindowState;
    movieWindowState = 0;
  }

  CMainFrame* mainFrame;
  if (AfxGetThread() != 0) {
    mainFrame = static_cast<CMainFrame*>(AfxGetThread()->GetMainWnd());
  } else {
    mainFrame = 0;
  }
  mainFrame->SetBackgroundColorAndInvalidate(kTiledBackdropSentinelColor);

  g_pSfxPlaybackSystem->RequestDirectSoundInitIfAllowed();
}

// FUNCTION: IMPERIALISM 0x005e23f0
void TMovieView::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  TView* owner = GetWindow();
  CWnd* nativeWindow = owner->nativeWindow;
  HWND parentHwnd = 0;
  if (nativeWindow != 0) {
    parentHwnd = nativeWindow->m_hWnd;
  }

  movieWindowState = new MciMovieWindowState(parentHwnd);
}

// FUNCTION: IMPERIALISM 0x005e2490
void TMovieView::Draw(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x005e24b0
bool TMovieView::OpenMoviePathAndDetachOnSuccess(LPCSTR moviePath) {
  if (movieWindowState != 0) {
    return movieWindowState->OpenAndCenter(moviePath);
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005e24e0
void TMovieView::PlayTheMovie() {
  if (movieWindowState != 0) {
    movieWindowState->Play();
  }
}

// FUNCTION: IMPERIALISM 0x005e2500
void TMovieView::StopMovie() {
  if (movieWindowState != 0) {
    movieWindowState->Stop();
  }
}

// FUNCTION: IMPERIALISM 0x005e2520
bool TMovieView::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (movieWindowState != 0) {
    movieWindowState->Stop();
  }
  return TPicture::HandleMouseDown(point, event, origin);
}
