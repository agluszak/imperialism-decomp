#pragma once

#include "game/mfc.h"
#include "game/globals/shared_globals.h"

#define GAME_FAIL_NIL_POINTER()                                                                    \
  MessageBoxA(NULL, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30)
