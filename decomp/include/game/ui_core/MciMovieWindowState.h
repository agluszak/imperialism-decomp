#pragma once

#include "game/mfc.h"

#define NOAVIFILE
#include <vfw.h>

struct MciMovieWindowState {
  MciMovieWindowState(HWND parentHwnd);

  void Close();                         // send WM_CLOSE to hwnd
  bool OpenAndCenter(LPCSTR moviePath); // MCIWNDM_OPENA, center on success
  bool Play();                          // MCI_PLAY
  bool Stop();                          // MCI_STOP (also used to skip)

  HWND hwnd;
  LRESULT lastResult;
};
ASSERT_SIZE(MciMovieWindowState, 0x08);

const DWORD kMciMovieWindowCreateStyle = 0x5000410a;
// The movie window is an MCIWnd driven with MCIWNDM_OPENA and raw MCI_PLAY/MCI_STOP messages.
