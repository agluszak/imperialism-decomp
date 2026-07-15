#pragma once

#include "game/mfc.h"

// Only need the MCIWnd control class; skip the AVIFile COM interfaces (avoids
// pulling in ole2.h).
#define NOAVIFILE
#include <vfw.h>

// Small non-polymorphic state block owned by TMovieView (this->movieWindowState). Every
// member here is a genuine __thiscall method on this struct in the original (verified via
// listing at 0x492f60/0x492fa0/0x492fc0/0x493090/0x4930d0 — each reads/writes through
// `in_ECX`, not an explicit pointer argument), not a free function taking the state as a
// parameter.
struct MciMovieWindowState {
  MciMovieWindowState(HWND parentHwnd); // 0x492f60

  void Close();                         // 0x492fa0 — send WM_CLOSE to hwnd
  bool OpenAndCenter(LPCSTR moviePath); // 0x492fc0 — MCIWNDM_OPENA, center on success
  bool Play();                          // 0x493090 — MCI_PLAY
  bool Stop();                          // 0x4930d0 — MCI_STOP (also used to skip)

  HWND hwnd;
  LRESULT lastResult;
};
ASSERT_SIZE(MciMovieWindowState, 0x08);

const DWORD kMciMovieWindowCreateStyle = 0x5000410a;
// The movie window is a standard MCIWnd; the game drives it by sending it MCIWNDM_OPENA
// (open a file) and, because MCIWnd relays MCI command messages to its device, the raw
// MCI_PLAY / MCI_STOP command messages (from <vfw.h> / <mmsystem.h>).
