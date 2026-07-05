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
const UINT kMciMovieOpenMessage = 0x499;
const UINT kMciMoviePlayMessage = 0x806;
const UINT kMciMoviePollMessage = 0x808;
