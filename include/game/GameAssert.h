#pragma once

#include "game/mfc.h"
#include "game/globals/shared_globals.h"

// The original passes the shared UI message globals (not inline string literals) to
// the nil-pointer message box.
#define GAME_FAIL_NIL_POINTER()                                                                    \
  MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30)
