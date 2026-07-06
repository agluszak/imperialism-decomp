#pragma once

#include "game/mfc.h"

// Only need the MCIWnd control class; skip the AVIFile COM interfaces (avoids
// pulling in ole2.h).
#define NOAVIFILE
#include <vfw.h>

struct MciMovieWindowState {
  HWND hwnd;
  LRESULT lastResult;
};
ASSERT_SIZE(MciMovieWindowState, 0x08);

const DWORD kMciMovieWindowCreateStyle = 0x5000410a;
// The movie window is a standard MCIWnd; the game drives it by sending it MCIWNDM_OPENA
// (open a file) and, because MCIWnd relays MCI command messages to its device, the raw
// MCI_PLAY / MCI_STOP command messages (from <vfw.h> / <mmsystem.h>).
