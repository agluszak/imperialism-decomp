#include "game/assets/TMovieView.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_core/CMainFrame.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/MciMovieWindowState.h"

// SYNTHETIC: IMPERIALISM 0x005e2100
// TMovieView::CreateObject

IMPLEMENT_DYNCREATE(TMovieView, TPicture)

// The original calls AfxGetThread() twice (once to null-check, once to fetch
// GetMainWnd() through it) rather than caching the result across the branch — this is
// the standard MSVC500 "call again to use" idiom for a value that isn't worth spilling
// across a conditional. Reproduced verbatim (not factored into a helper) to match.
// Note: movieWindowState is not explicitly zeroed here (listing at 0x5e2230 has no
// write to this+0x90) — it stays whatever the allocator handed back until
// DoPostCreate assigns it. Matches the original; not "fixed" to zero-init.
// FUNCTION: IMPERIALISM 0x005e2230
TMovieView::TMovieView() : TPicture() {
  g_pSfxPlaybackSystem->ClearDirectSoundInitPendingAndResetState();
  g_pSfxPlaybackSystem->StopCdAudioPlayback(1);

  CMainFrame* mainFrame;
  if (AfxGetThread() != 0) {
    mainFrame = static_cast<CMainFrame*>(AfxGetThread()->GetMainWnd());
  } else {
    mainFrame = 0;
  }
  mainFrame->SetBackgroundColorAndInvalidate(PALETTEINDEX(0));
}

// The scalar deleting destructor is compiler-generated from the virtual dtor; it is a
// thin wrapper that calls the real destructor body below (verified at 0x5e22f0: a
// 30-byte thunk that calls 0x4058df -> 0x5e2320) then conditionally frees.
// SYNTHETIC: IMPERIALISM 0x005e22f0
// TMovieView::`scalar deleting destructor'

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
  CWnd* nativeWindow = owner->nativeWindow50;
  HWND parentHwnd = 0;
  if (nativeWindow != 0) {
    parentHwnd = nativeWindow->m_hWnd;
  }

  movieWindowState = new MciMovieWindowState(parentHwnd);
}

// FUNCTION: IMPERIALISM 0x005e2490
void TMovieView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x005e24b0
bool TMovieView::OpenMoviePathAndDetachOnSuccess(LPCSTR moviePath) {
  if (movieWindowState != 0) {
    return movieWindowState->OpenAndCenter(moviePath);
  }
  return false;
}

// Return type is void, not bool: the listing at 0x005e24e0 (`test ecx,ecx; jz +5;
// jmp Play(); ret`) never sets eax/al on the null path, and both callers
// (PlayMovieClipAndDispatchTurnStateFollowup at 0x5dfc10, via thunk 0x401839) discard
// the call's result entirely — there is no bool being consumed here.
// FUNCTION: IMPERIALISM 0x005e24e0
void TMovieView::PlayMovieIfActive() {
  if (movieWindowState != 0) {
    movieWindowState->Play();
  }
}

// Stop (skip) the movie: sends MCI_STOP, which makes the MCIWnd notify its parent with
// MCIWNDM_NOTIFYMODE/MCI_MODE_STOP -> CIncludeView::OnMciNotifyMode advances the turn state.
// Same void-return shape as PlayMovieIfActive above (0x005e2500 listing; caller
// DoKeyEvent at 0x4ffd70 via thunk 0x40485e also discards the result).
// FUNCTION: IMPERIALISM 0x005e2500
void TMovieView::StopMovieIfActive() {
  if (movieWindowState != 0) {
    movieWindowState->Stop();
  }
}

// FUNCTION: IMPERIALISM 0x005e2520
char TMovieView::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (movieWindowState != 0) {
    movieWindowState->Stop();
  }
  return TPicture::HandleMouseDown(point, event, origin);
}

// SYNTHETIC: IMPERIALISM 0x005e2210
// TMovieView::GetRuntimeClass
