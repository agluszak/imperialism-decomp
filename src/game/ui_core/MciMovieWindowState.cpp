#include "game/MciMovieWindowState.h"

#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00492f60
MciMovieWindowState::MciMovieWindowState(HWND parentHwnd) {
  AFX_MODULE_STATE* moduleState = AfxGetModuleState();
  hwnd = MCIWndCreateA(parentHwnd, moduleState->m_hCurrentInstanceHandle,
                       kMciMovieWindowCreateStyle, 0);
}

// FUNCTION: IMPERIALISM 0x00492fa0
void MciMovieWindowState::Close() {
  SendMessageA(hwnd, WM_CLOSE, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00492fc0
bool MciMovieWindowState::OpenAndCenter(LPCSTR moviePath) {
  lastResult = SendMessageA(hwnd, MCIWNDM_OPENA, 0, reinterpret_cast<LPARAM>(moviePath));
  if (lastResult == 0) {
    CWnd window;
    window.Attach(hwnd);
    window.CenterWindow();
    window.Detach();
  }
  return lastResult == 0;
}

// FUNCTION: IMPERIALISM 0x00493090
bool MciMovieWindowState::Play() {
  lastResult = SendMessageA(hwnd, MCI_PLAY, 0, 0);
  return lastResult == 0;
}

// FUNCTION: IMPERIALISM 0x004930d0
bool MciMovieWindowState::Stop() {
  lastResult = SendMessageA(hwnd, MCI_STOP, 0, 0);
  return lastResult == 0;
}
