#pragma once

#include "game/mfc.h"

// Writes g_cachedShowSplashFlag (GLOBAL 0x006a2018) — see global_data_tables.cpp.
void SetCachedShowSplashFlag(BOOL showSplash);
